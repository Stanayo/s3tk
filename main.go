package main

import (
	"bufio"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"
)

type S3Test struct {
	BucketName    string
	CanList       bool
	CanUpload     bool
	CanDelete     bool
	CanTakeover   bool
	BucketExists  bool
}

var colors = []string{
	"\033[31m", // Red
	"\033[32m", // Green
	"\033[33m", // Yellow
	"\033[34m", // Blue
	"\033[35m", // Magenta
	"\033[36m", // Cyan
	"\033[91m", // Bright Red
	"\033[92m", // Bright Green
	"\033[93m", // Bright Yellow
	"\033[94m", // Bright Blue
	"\033[95m", // Bright Magenta
	"\033[96m", // Bright Cyan
}

const reset = "\033[0m"

func getRandomColor() string {
	rand.Seed(time.Now().UnixNano())
	return colors[rand.Intn(len(colors))]
}

func printBanner() {
	color1 := getRandomColor()
	color2 := getRandomColor()
	color3 := getRandomColor()
	
	banner := `
%s███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗     ██╗ █████╗  █████╗  █████╗ ██╗  ██╗%s
%s██╔════╝╚════██╗██╔════╝██╔════╝██╔══██╗████╗  ██║     ██║██╔══██╗██╔══██╗██╔══██╗██║  ██║%s
%s███████╗ █████╔╝███████╗██║     ███████║██╔██╗ ██║     ██║███████║███████║███████║███████║%s
%s╚════██║ ╚═══██╗╚════██║██║     ██╔══██║██║╚██╗██║██   ██║██╔══██║██╔══██║██╔══██║██╔══██║%s
%s███████║██████╔╝███████║╚██████╗██║  ██║██║ ╚████║╚█████╔╝██║  ██║██║  ██║██║  ██║██║  ██║%s
%s╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝%s

%s                    S3 Bucket Security Scanner for Bug Bounty%s
%s                          Created for Penetration Testing%s
`
	
	fmt.Printf(banner, 
		color1, reset,
		color2, reset,
		color3, reset,
		color1, reset,
		color2, reset,
		color3, reset,
		color1, reset,
		color2, reset,
	)
	fmt.Println()
}

func extractBucketName(s3url string) string {
	s3url = strings.TrimSpace(s3url)
	
	// Handle different S3 URL formats
	if strings.HasPrefix(s3url, "https://") {
		s3url = strings.TrimPrefix(s3url, "https://")
	} else if strings.HasPrefix(s3url, "http://") {
		s3url = strings.TrimPrefix(s3url, "http://")
	}
	
	// Extract bucket name from different formats
	if strings.Contains(s3url, ".s3.") {
		// Format: bucket-name.s3.region.amazonaws.com
		return strings.Split(s3url, ".")[0]
	} else if strings.HasPrefix(s3url, "s3.") {
		// Format: s3.region.amazonaws.com/bucket-name
		parts := strings.Split(s3url, "/")
		if len(parts) > 1 {
			return parts[1]
		}
	}
	
	// If it's just the bucket name
	if !strings.Contains(s3url, "/") && !strings.Contains(s3url, ".") {
		return s3url
	}
	
	return s3url
}

func testS3List(bucketName string) bool {
	urls := []string{
		fmt.Sprintf("https://%s.s3.amazonaws.com/", bucketName),
		fmt.Sprintf("https://s3.amazonaws.com/%s/", bucketName),
	}
	
	for _, url := range urls {
		resp, err := http.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		
		bodyStr := string(body)
		
		// Check if we can list objects
		if resp.StatusCode == 200 && (strings.Contains(bodyStr, "<ListBucketResult") || 
			strings.Contains(bodyStr, "<Contents>") ||
			strings.Contains(bodyStr, "<?xml")) {
			return true
		}
	}
	
	return false
}

func testS3Upload(bucketName string) bool {
	testFile := "test-upload-" + fmt.Sprintf("%d", time.Now().Unix()) + ".txt"
	testContent := "This is a test file for S3 misconfiguration detection"
	
	urls := []string{
		fmt.Sprintf("https://%s.s3.amazonaws.com/%s", bucketName, testFile),
		fmt.Sprintf("https://s3.amazonaws.com/%s/%s", bucketName, testFile),
	}
	
	for _, url := range urls {
		req, err := http.NewRequest("PUT", url, strings.NewReader(testContent))
		if err != nil {
			continue
		}
		
		req.Header.Set("Content-Type", "text/plain")
		
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		// Check if upload was successful
		if resp.StatusCode == 200 || resp.StatusCode == 201 {
			// Try to clean up the test file
			deleteReq, _ := http.NewRequest("DELETE", url, nil)
			client.Do(deleteReq)
			return true
		}
	}
	
	return false
}

func testS3Delete(bucketName string) bool {
	// Create a test file first
	testFile := "test-delete-" + fmt.Sprintf("%d", time.Now().Unix()) + ".txt"
	
	urls := []string{
		fmt.Sprintf("https://%s.s3.amazonaws.com/%s", bucketName, testFile),
		fmt.Sprintf("https://s3.amazonaws.com/%s/%s", bucketName, testFile),
	}
	
	for _, url := range urls {
		// Try to delete (even if file doesn't exist, we check permissions)
		req, err := http.NewRequest("DELETE", url, nil)
		if err != nil {
			continue
		}
		
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		// If we get 204 (No Content) or 200, delete permissions exist
		// If we get 404, the object doesn't exist but we might have delete permissions
		if resp.StatusCode == 204 || resp.StatusCode == 200 || resp.StatusCode == 404 {
			// Check the response for permission indicators
			body, _ := io.ReadAll(resp.Body)
			bodyStr := string(body)
			
			// If we don't get an AccessDenied error, we might have delete permissions
			if !strings.Contains(bodyStr, "AccessDenied") && !strings.Contains(bodyStr, "Forbidden") {
				return true
			}
		}
	}
	
	return false
}

func checkBucketExistence(bucketName string) bool {
	urls := []string{
		fmt.Sprintf("https://%s.s3.amazonaws.com/", bucketName),
		fmt.Sprintf("https://s3.amazonaws.com/%s/", bucketName),
	}
	
	for _, url := range urls {
		resp, err := http.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		// If bucket exists, we should get some response (200, 403, etc.)
		// If bucket doesn't exist, we typically get 404
		if resp.StatusCode != 404 {
			return true
		}
		
		// Check response body for specific error messages
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		
		bodyStr := string(body)
		// If we get NoSuchBucket error, the bucket definitely doesn't exist
		if strings.Contains(bodyStr, "NoSuchBucket") || strings.Contains(bodyStr, "The specified bucket does not exist") {
			return false
		}
	}
	
	return true // Default to assuming bucket exists if unclear
}

func testBucketTakeover(bucketName string) bool {
	// First check if bucket exists
	if checkBucketExistence(bucketName) {
		return false // Can't takeover existing bucket
	}
	
	// Test different regions where bucket might be claimed
	regions := []string{
		"us-east-1",
		"us-west-1", 
		"us-west-2",
		"eu-west-1",
		"eu-central-1",
		"ap-southeast-1",
		"ap-northeast-1",
	}
	
	for _, region := range regions {
		url := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/", bucketName, region)
		
		resp, err := http.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		// Check for specific error patterns that indicate takeover potential
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}
		
		bodyStr := string(body)
		
		// Look for error messages that indicate the bucket doesn't exist
		// and could potentially be claimed
		if strings.Contains(bodyStr, "NoSuchBucket") ||
		   strings.Contains(bodyStr, "The specified bucket does not exist") ||
		   resp.StatusCode == 404 {
			return true
		}
	}
	
	return false
}

func scanS3Bucket(bucketName string) S3Test {
	result := S3Test{BucketName: bucketName}
	
	fmt.Printf("[*] Scanning bucket: %s\n", bucketName)
	
	// Check if bucket exists first
	fmt.Print("  [+] Checking bucket existence... ")
	result.BucketExists = checkBucketExistence(bucketName)
	if result.BucketExists {
		fmt.Printf("%s[EXISTS]%s\n", "\033[92m", reset)
	} else {
		fmt.Printf("%s[NOT FOUND]%s\n", "\033[93m", reset)
	}
	
	// Test for bucket takeover if bucket doesn't exist
	if !result.BucketExists {
		fmt.Print("  [+] Testing TAKEOVER potential... ")
		result.CanTakeover = testBucketTakeover(bucketName)
		if result.CanTakeover {
			fmt.Printf("%s[VULNERABLE]%s\n", "\033[91m", reset)
		} else {
			fmt.Printf("%s[SECURE]%s\n", "\033[92m", reset)
		}
	}
	
	// Only test other permissions if bucket exists
	if result.BucketExists {
		// Test LIST permissions
		fmt.Print("  [+] Testing LIST permissions... ")
		result.CanList = testS3List(bucketName)
		if result.CanList {
			fmt.Printf("%s[VULNERABLE]%s\n", "\033[91m", reset)
		} else {
			fmt.Printf("%s[SECURE]%s\n", "\033[92m", reset)
		}
		
		// Test UPLOAD permissions
		fmt.Print("  [+] Testing UPLOAD permissions... ")
		result.CanUpload = testS3Upload(bucketName)
		if result.CanUpload {
			fmt.Printf("%s[VULNERABLE]%s\n", "\033[91m", reset)
		} else {
			fmt.Printf("%s[SECURE]%s\n", "\033[92m", reset)
		}
		
		// Test DELETE permissions
		fmt.Print("  [+] Testing DELETE permissions... ")
		result.CanDelete = testS3Delete(bucketName)
		if result.CanDelete {
			fmt.Printf("%s[VULNERABLE]%s\n", "\033[91m", reset)
		} else {
			fmt.Printf("%s[SECURE]%s\n", "\033[92m", reset)
		}
	}
	
	return result
}

func printResults(results []S3Test) {
	fmt.Printf("\n%s╔══════════════════════════════════════════════════════════════╗%s\n", "\033[93m", reset)
	fmt.Printf("%s║                        SCAN RESULTS                          ║%s\n", "\033[93m", reset)
	fmt.Printf("%s╚══════════════════════════════════════════════════════════════╝%s\n\n", "\033[93m", reset)
	
	vulnerableBuckets := 0
	takeoverBuckets := 0
	
	for _, result := range results {
		if result.CanList || result.CanUpload || result.CanDelete || result.CanTakeover {
			vulnerableBuckets++
			
			if result.CanTakeover {
				takeoverBuckets++
				fmt.Printf("%s[TAKEOVER POSSIBLE]%s %s\n", "\033[95m", reset, result.BucketName)
				fmt.Printf("  └─ %s[TAKEOVER]%s Bucket doesn't exist - can be claimed for subdomain takeover\n", "\033[35m", reset)
				fmt.Println()
			} else {
				fmt.Printf("%s[MISCONFIGURED]%s %s\n", "\033[91m", reset, result.BucketName)
				
				if result.CanList {
					fmt.Printf("  └─ %s[LIST]%s Public read access - can enumerate bucket contents\n", "\033[31m", reset)
				}
				if result.CanUpload {
					fmt.Printf("  └─ %s[UPLOAD]%s Public write access - can upload malicious files\n", "\033[31m", reset)
				}
				if result.CanDelete {
					fmt.Printf("  └─ %s[DELETE]%s Public delete access - can remove objects\n", "\033[31m", reset)
				}
				fmt.Println()
			}
		} else {
			if result.BucketExists {
				fmt.Printf("%s[SECURE]%s %s\n", "\033[92m", reset, result.BucketName)
			} else {
				fmt.Printf("%s[NOT FOUND]%s %s (bucket doesn't exist but not exploitable)\n", "\033[93m", reset, result.BucketName)
			}
		}
	}
	
	fmt.Printf("\n%s╔══════════════════════════════════════════════════════════════╗%s\n", "\033[96m", reset)
	fmt.Printf("%s║                          SUMMARY                             ║%s\n", "\033[96m", reset)
	fmt.Printf("%s╚══════════════════════════════════════════════════════════════╝%s\n", "\033[96m", reset)
	fmt.Printf("Total buckets scanned: %d\n", len(results))
	fmt.Printf("Vulnerable buckets found: %s%d%s\n", "\033[91m", vulnerableBuckets, reset)
	fmt.Printf("Takeover opportunities: %s%d%s\n", "\033[95m", takeoverBuckets, reset)
	fmt.Printf("Secure buckets: %s%d%s\n", "\033[92m", len(results)-vulnerableBuckets, reset)
}

func main() {
	printBanner()
	
	fmt.Printf("%s[INFO]%s Reading S3 bucket URLs from stdin...\n", "\033[94m", reset)
	fmt.Printf("%s[INFO]%s Supported formats: bucket-name, https://bucket.s3.amazonaws.com, s3://bucket-name\n\n", "\033[94m", reset)
	
	var buckets []string
	scanner := bufio.NewScanner(os.Stdin)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			bucketName := extractBucketName(line)
			if bucketName != "" {
				buckets = append(buckets, bucketName)
			}
		}
	}
	
	if err := scanner.Err(); err != nil {
		fmt.Printf("%s[ERROR]%s Error reading from stdin: %v\n", "\033[91m", reset, err)
		os.Exit(1)
	}
	
	if len(buckets) == 0 {
		fmt.Printf("%s[ERROR]%s No valid S3 bucket URLs found in input\n", "\033[91m", reset)
		os.Exit(1)
	}
	
	fmt.Printf("%s[INFO]%s Found %d bucket(s) to scan\n\n", "\033[94m", reset, len(buckets))
	
	var results []S3Test
	
	for _, bucket := range buckets {
		result := scanS3Bucket(bucket)
		results = append(results, result)
		fmt.Println()
	}
	
	printResults(results)
}
