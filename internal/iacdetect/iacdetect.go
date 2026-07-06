// Package iacdetect derives a baseline set of architecture components from a
// directory's infrastructure-as-code, so a threat model can be bootstrapped from
// what the repo actually declares rather than typed by hand. It is deterministic
// and dependency-light: Terraform resources are matched by type, and Kubernetes
// / docker-compose manifests by kind and image. Every detected component maps to
// a threatlib tech so STRIDE can be enumerated over it.
//
// This is a heuristic baseline, not a full IaC parser. It favors recall (surface
// the obvious database, object store, API, auth service) over precision; a human
// edits the result. It never executes anything and reads at most a bounded slice
// of each file.
package iacdetect

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Component is one detected architecture node.
type Component struct {
	Name   string `json:"name"`
	Tech   string `json:"tech"`   // a threatlib tech id
	Source string `json:"source"` // the file it was detected in (repo-relative)
}

// maxFileBytes bounds how much of any one file is read.
const maxFileBytes = 512 * 1024

// tfResourceTech maps a Terraform resource type prefix to a threatlib tech. The
// longest matching prefix wins, so "aws_db_instance" beats a broader rule.
var tfResourceTech = []struct{ prefix, tech string }{
	{"aws_db_instance", "database"},
	{"aws_rds_cluster", "database"},
	{"aws_dynamodb_table", "database"},
	{"aws_elasticache", "database"},
	{"azurerm_postgresql", "database"},
	{"azurerm_mysql", "database"},
	{"azurerm_sql", "database"},
	{"google_sql_database_instance", "database"},
	{"aws_s3_bucket", "object-store"},
	{"azurerm_storage_account", "object-store"},
	{"google_storage_bucket", "object-store"},
	{"aws_lb", "api-service"},
	{"aws_alb", "api-service"},
	{"aws_elb", "api-service"},
	{"aws_api_gateway", "api-service"},
	{"aws_apigatewayv2", "api-service"},
	{"aws_lambda_function", "api-service"},
	{"aws_ecs_service", "api-service"},
	{"aws_ecs_task_definition", "api-service"},
	{"google_cloud_run", "api-service"},
	{"aws_cognito", "auth-service"},
	{"auth0_", "auth-service"},
	{"okta_", "auth-service"},
	{"aws_cloudfront_distribution", "web-app"},
	{"aws_amplify_app", "web-app"},
}

// cfnTypeTech maps a CloudFormation resource Type token to a tech.
var cfnTypeTech = []struct{ contains, tech string }{
	{"AWS::RDS::", "database"},
	{"AWS::DynamoDB::", "database"},
	{"AWS::ElastiCache::", "database"},
	{"AWS::S3::Bucket", "object-store"},
	{"AWS::ElasticLoadBalancingV2::", "api-service"},
	{"AWS::ApiGateway", "api-service"},
	{"AWS::Lambda::Function", "api-service"},
	{"AWS::ECS::Service", "api-service"},
	{"AWS::Cognito::", "auth-service"},
	{"AWS::CloudFront::", "web-app"},
}

// imageTech maps a substring of a container image to a tech (k8s / compose).
var imageTech = []struct{ contains, tech string }{
	{"postgres", "database"},
	{"mysql", "database"},
	{"mariadb", "database"},
	{"mongo", "database"},
	{"redis", "database"},
	{"cassandra", "database"},
	{"minio", "object-store"},
	{"nginx", "web-app"},
	{"httpd", "web-app"},
	{"keycloak", "auth-service"},
	{"dex", "auth-service"},
}

var (
	tfResourceRe = regexp.MustCompile(`(?m)^\s*resource\s+"([a-z0-9_]+)"\s+"([a-zA-Z0-9_-]+)"`)
	cfnTypeRe    = regexp.MustCompile(`Type:\s*["']?(AWS::[A-Za-z0-9:]+)`)
	k8sKindRe    = regexp.MustCompile(`(?m)^\s*kind:\s*["']?([A-Za-z]+)`)
	imageRe      = regexp.MustCompile(`(?m)^\s*image:\s*["']?([^\s"']+)`)
)

// skipDirs are never walked (vendored code, VCS, the server's own workspace).
var skipDirs = map[string]bool{".git": true, ".appsec": true, "node_modules": true, "vendor": true, ".terraform": true}

// Scan walks dir and returns the detected components, deduplicated by
// name+tech and sorted. A missing dir returns an empty slice, not an error.
func Scan(dir string) ([]Component, error) {
	seen := map[string]Component{}
	add := func(name, tech, source string) {
		if tech == "" || name == "" {
			return
		}
		key := strings.ToLower(name) + "\x00" + tech
		if _, ok := seen[key]; !ok {
			seen[key] = Component{Name: name, Tech: tech, Source: source}
		}
	}

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries, keep walking
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		name := d.Name()
		lower := strings.ToLower(name)
		switch {
		case strings.HasSuffix(lower, ".tf"):
			scanTerraform(path, rel, add)
		case isCompose(lower):
			scanImages(path, rel, add)
		case strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml"):
			scanKubernetes(path, rel, add)
		case strings.HasSuffix(lower, ".json") || lower == "template.json":
			scanCloudFormation(path, rel, add)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	out := make([]Component, 0, len(seen))
	for _, c := range seen {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tech != out[j].Tech {
			return out[i].Tech < out[j].Tech
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func scanTerraform(path, rel string, add func(name, tech, source string)) {
	body := readCapped(path)
	for _, m := range tfResourceRe.FindAllStringSubmatch(body, -1) {
		rtype, rname := m[1], m[2]
		if tech := techForTFResource(rtype); tech != "" {
			add(rname, tech, rel)
		}
	}
}

func techForTFResource(rtype string) string {
	best, bestLen := "", -1
	for _, r := range tfResourceTech {
		if strings.HasPrefix(rtype, r.prefix) && len(r.prefix) > bestLen {
			best, bestLen = r.tech, len(r.prefix)
		}
	}
	return best
}

func scanCloudFormation(path, rel string, add func(name, tech, source string)) {
	body := readCapped(path)
	if !strings.Contains(body, "AWS::") {
		return
	}
	for _, m := range cfnTypeRe.FindAllStringSubmatch(body, -1) {
		t := m[1]
		for _, r := range cfnTypeTech {
			if strings.Contains(t, r.contains) {
				add(shortType(t), r.tech, rel)
				break
			}
		}
	}
}

func scanKubernetes(path, rel string, add func(name, tech, source string)) {
	body := readCapped(path)
	// A workload kind plus its container image: the image usually reveals the
	// tech (postgres → database); otherwise a Deployment/StatefulSet is a service.
	kinds := k8sKindRe.FindAllStringSubmatch(body, -1)
	if len(kinds) == 0 {
		return
	}
	matchedImage := scanImages(path, rel, add)
	if matchedImage {
		return
	}
	for _, m := range kinds {
		switch m[1] {
		case "Deployment", "StatefulSet", "DaemonSet", "Pod", "ReplicaSet":
			add(baseName(rel), "api-service", rel)
		}
	}
}

func isCompose(name string) bool {
	return name == "docker-compose.yml" || name == "docker-compose.yaml" ||
		name == "compose.yml" || name == "compose.yaml"
}

// scanImages adds a component per recognized container image; returns whether
// any image matched.
func scanImages(path, rel string, add func(name, tech, source string)) bool {
	body := readCapped(path)
	matched := false
	for _, m := range imageRe.FindAllStringSubmatch(body, -1) {
		img := strings.ToLower(m[1])
		for _, r := range imageTech {
			if strings.Contains(img, r.contains) {
				add(imageName(m[1]), r.tech, rel)
				matched = true
				break
			}
		}
	}
	return matched
}

func readCapped(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	var b strings.Builder
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		line := sc.Text()
		n += len(line) + 1
		if n > maxFileBytes {
			break
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func shortType(t string) string {
	parts := strings.Split(t, "::")
	return parts[len(parts)-1]
}
func baseName(rel string) string {
	return strings.TrimSuffix(filepath.Base(rel), filepath.Ext(rel))
}
func imageName(img string) string {
	img = strings.SplitN(img, ":", 2)[0] // drop the tag
	parts := strings.Split(img, "/")
	return parts[len(parts)-1]
}
