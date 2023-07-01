// Copyright 2019 @dukebarman. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "net/http"
    "os"
    "regexp"
    "strings"

    "github.com/PuerkitoBio/goquery"
)

type bulletinData struct {
    BulletinLink string
    Vulns        []cveData
}

type cveData struct {
    CveID       string
    PatchLinks  []string
    CveType     string
    CveSeverity string
    AVersions   []string // for android versions
}

func CvelinkScrape(bulletinLink string, unpublish bool, filterAndroid string) bulletinData {
    res, err := http.Get(bulletinLink)
    if err != nil {
        log.Fatal(err)
    }
    defer res.Body.Close()
    if res.StatusCode != 200 {
        log.Fatalf("status code error: %d %s", res.StatusCode, res.Status)
    }

    doc, err := goquery.NewDocumentFromReader(res.Body)
    if err != nil {
        log.Fatal(err)
    }

    var bData bulletinData
    bData.BulletinLink = bulletinLink

    doc.Find("table").Each(func(i int, tr *goquery.Selection) {
        selectionTh := tr.Find("th")
        tableHeader := map[string]int{
            "cve":      0,
            "link":     1,
            "type":     -1,
            "severity": -1,
            "aversion": -1,
        }

        if selectionTh.Eq(0).Text() == "CVE" {
            for i := range selectionTh.Nodes {
                if selectionTh.Eq(i).Text() == "Severity" {
                    tableHeader["severity"] = i
                }
                if selectionTh.Eq(i).Text() == "Type" {
                    tableHeader["type"] = i
                }
                if strings.Contains(selectionTh.Eq(i).Text(), "versions") {
                    tableHeader["aversion"] = i
                }
            }
        } else {
            tableHeader["cve"] = -1
        }

        tr.Find("tr").Each(func(i int, td *goquery.Selection) {
            selectionTd := td.Find("td")
            var cveLinks []string
            var androidVersions []string
            var cve string
            var cveType string
            var cveSeverity string

            selectionTd.Eq(tableHeader["link"]).Find("a").Each(func(i int, links *goquery.Selection) {
                customLink, _ := links.Attr("href")
                pattern := regexp.MustCompile(`(?:(?:source|android\.googlesource\.com|git)\b)`) // choose popular domains with sources
                res := pattern.FindStringSubmatch(customLink)
                if len(res) > 0 {
                    if customLink[:2] == "//" { // I don't know why, but sometimes links start from "//"
                        customLink = "https:" + customLink
                    }
                    cveLinks = append(cveLinks, customLink)
                } else if strings.Contains(customLink, "asterisk") && unpublish { // in most cases this is bug from Qualcomm with closed sources
                    cveLinks = append(cveLinks, "unpublished")
                }
            })

            if tableHeader["cve"] == 0 {
                cve = selectionTd.Eq(tableHeader["cve"]).Text()
                cve = strings.Trim(cve, " \n")
            }
            if tableHeader["type"] > 0 {
                cveType = selectionTd.Eq(tableHeader["type"]).Text()
            } else {
                cveType = "N/A"
            }
            if tableHeader["severity"] > 0 {
                cveSeverity = selectionTd.Eq(tableHeader["severity"]).Text()
            }
            if tableHeader["aversion"] > 0 {
                androidVersions = strings.Fields(strings.ReplaceAll(
                    selectionTd.Eq(
                        tableHeader["aversion"]).Text(),
                    ",",
                    ""))
            }

            if cve != "" && len(cveLinks) > 0 {
                cveTr := cveData{
                    CveID:       cve,
                    PatchLinks:  cveLinks,
                    CveType:     cveType,
                    CveSeverity: cveSeverity,
                    AVersions:   androidVersions,
                }
                if (len(filterAndroid) > 0 && SliceContains(androidVersions, filterAndroid)) ||
                    (len(filterAndroid) == 0) {
                    bData.Vulns = append(bData.Vulns, cveTr)
                }
            }
        })
    })

    return bData
}

func SliceContains(a []string, x string) bool {
    for _, n := range a {
        if strings.Contains(x, n) {
            return true
        }
    }

    return false
}

func BulletinScrape() []string {
    res, err := http.Get("https://source.android.com/security/bulletin")
    if err != nil {
        log.Fatal(err)
    }

    defer res.Body.Close()
    if res.StatusCode != 200 {
        log.Fatalf("status code error: %d %s", res.StatusCode, res.Status)
    }

    doc, err := goquery.NewDocumentFromReader(res.Body)
    if err != nil {
        log.Fatal(err)
    }

    var bulletinUrls []string
    var validBulletinUrl = regexp.MustCompile(`/security/bulletin/\d+-\d+-\d+`)
    doc.Find("a").Each(func(i int, link *goquery.Selection) {
        bulletinUrl, _ := link.Attr("href")
        if !SliceContains(bulletinUrls, bulletinUrl) &&
            validBulletinUrl.MatchString(bulletinUrl) {
            bulletinUrls = append(bulletinUrls, bulletinUrl)
        }
    })

    return bulletinUrls
}

func PrintJSONResults(bDatas []bulletinData, fileOutput string) error {
    b, err := json.Marshal(bDatas)
    if err != nil {
        log.Fatal(err)
        return err
    }

    if len(fileOutput) > 0 {
        w, err := os.Create(fileOutput)
        if err != nil {
            log.Fatal(err)
            return err
        }
        defer w.Close()

        line := fmt.Sprintln(string(b))
        _, err = w.WriteString(line)
        if err != nil {
            log.Fatal(err)
            return err
        }
    } else {
        fmt.Println(string(b))
    }

    return nil
}

func PrintMDResults(bDatas []bulletinData) error {
    for _, oneBulletin := range bDatas {
        fmt.Printf("# %s\n\n", oneBulletin.BulletinLink)
        for _, oneCve := range oneBulletin.Vulns {
            patchString := ""
            for _, oneLink := range oneCve.PatchLinks {
                patchString += " [Patch](" + oneLink + ")"
            }
            if len(oneCve.AVersions) > 0 {
                fmt.Printf("* %s (%s, %s):%s\n", oneCve.CveID, oneCve.CveType, oneCve.CveSeverity, patchString)
                fmt.Printf("Android affected versions: %s", strings.Join(oneCve.AVersions, ","))
            } else {
                fmt.Printf("* %s (%s, %s):%s", oneCve.CveID, oneCve.CveType, oneCve.CveSeverity, patchString)
            }
            fmt.Println()
        }
    }
    return nil
}

func PrintResults(bDatas []bulletinData, jsonOutput bool, fileOutput string) error {
    if jsonOutput {
        return PrintJSONResults(bDatas, fileOutput)
    } else {
        return PrintMDResults(bDatas)
    }
}

func main() {
    // TODO: flag for filter by Type
    // TODO: flag for filter by Severity
    var bulletinUrl = flag.String("url", "last", "Parse needed Security Bulletin or last or all from https://source.android.com")
    var unpublish = flag.Bool("unpublish", false, "Show unpublished CVE")
    var outputJson = flag.Bool("json", false, "Output in json format")
    var outputFile = flag.String("output", "", "File name for output json")
    var androidVersion = flag.String("android", "", "Filter CVEs by Android version")

    flag.Usage = func() {
        fmt.Println("Usage of android-bulletin-harvester.go:")
        flag.PrintDefaults()
    }

    flag.Parse()

    var bulletinDatas []bulletinData
    if *bulletinUrl == "all" || *bulletinUrl == "last" {
        bulletinUrls := BulletinScrape()
        if *bulletinUrl == "last" {
            var bData = CvelinkScrape("https://source.android.com"+bulletinUrls[0], *unpublish, *androidVersion)
            bulletinDatas = append(bulletinDatas, bData)
        } else {
            for i := 0; i < len(bulletinUrls); i++ {
                var bData = CvelinkScrape("https://source.android.com"+bulletinUrls[i], *unpublish, *androidVersion)
                bulletinDatas = append(bulletinDatas, bData)
            }
        }
    } else {
        var bData = CvelinkScrape(*bulletinUrl, *unpublish, *androidVersion)
        bulletinDatas = append(bulletinDatas, bData)
    }
    PrintResults(bulletinDatas, *outputJson, *outputFile)
}
