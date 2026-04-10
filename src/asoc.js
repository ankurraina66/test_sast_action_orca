/*
Copyright 2022, 2024 HCL America, Inc.
Licensed under the Apache License, Version 2.0
*/

import got from 'got';
import * as constants from './constants.js';
import resultProcessor from './resultProcessor.js';
import settings from './settings.js';
import utils from './utils.js';
import fs from 'fs';

let token = null;

/*
-----------------------------------------
Login
-----------------------------------------
*/
function login(key, secret) {

    return new Promise((resolve, reject) => {

        if (!key || !secret) {
            reject("Missing API key/secret");
            return;
        }

        const url =
            settings.getServiceUrl() +
            constants.API_LOGIN;

        got.post(url, {
            json: {
                keyId: key,
                keySecret: secret,
                clientType: utils.getClientType()
            }
        })

        .then(res => {

            const body =
                JSON.parse(res.body);

            token =
                body.Token;

            resolve();

        })

        .catch(reject);

    });

}

/*
-----------------------------------------
Main entry
-----------------------------------------
*/
function getScanResults(scanId) {

    return new Promise((resolve, reject) => {

        const key =
            utils.sanitizeString(
                process.env.INPUT_ASOC_KEY
            );

        const secret =
            utils.sanitizeString(
                process.env.INPUT_ASOC_SECRET
            );

        login(key, secret)

        .then(() =>
            getNonCompliantIssues(scanId)
        )

        .then(resolve)

        .catch(reject);

    });

}

/*
-----------------------------------------
Fetch issue summary
-----------------------------------------
*/
function getNonCompliantIssues(scanId) {

    return new Promise((resolve, reject) => {

        const query =
            "?applyPolicies=All" +
            "&%24top=100" +
            "&%24apply=filter" +
            "%28Status%20eq%20%27Open%27" +
            "%20or%20Status%20eq%20%27New%27" +
            "%20or%20Status%20eq%20%27Reopened%27" +
            "%20or%20Status%20eq%20%27InProgress%27%29" +
            "%2Fgroupby%28%28Severity%29%2Caggregate" +
            "%28%24count%20as%20Count%29%29";

        const url =
            settings.getServiceUrl() +
            constants.API_ISSUES +
            scanId +
            query;

        got.get(url, {
            headers: getHeaders()
        })

        .then(res => {

            const json =
                JSON.parse(res.body);

            return resultProcessor
                .processResults(json.Items);

        })

        .then(result => {

            /*
            ---------------------------------
            Normalize result format
            fixes "result.forEach is not function"
            ---------------------------------
            */

            if (!result) {
                result = [];
            }

            if (!Array.isArray(result)) {

                result =
                    Object.keys(result).map(sev => ({

                        Severity: sev,
                        Count: result[sev]

                    }));

            }

            /*
            ---------------------------------
            Count severities
            ---------------------------------
            */

            const counts = {

                Critical: 0,
                High: 0,
                Medium: 0,
                Low: 0,
                Informational: 0

            };

            result.forEach(issue => {

                if (
                    issue &&
                    counts[issue.Severity] !== undefined
                ) {

                    counts[issue.Severity] +=
                        Number(issue.Count || 0);

                }

            });

            const total =
                Object.values(counts)
                .reduce(
                    (a,b)=>a+b,
                    0
                );

            /*
            ---------------------------------
            Risk level
            ---------------------------------
            */

            let risk =
                "No Risk";

            let icon =
                "⚪";

            if (counts.Critical > 0) {

                risk =
                    "Critical Risk";

                icon =
                    "🔴";

            }

            else if (counts.High > 0) {

                risk =
                    "High Risk";

                icon =
                    "🔴";

            }

            else if (counts.Medium > 0) {

                risk =
                    "Medium Risk";

                icon =
                    "🟡";

            }

            else if (counts.Low > 0) {

                risk =
                    "Low Risk";

                icon =
                    "🟢";

            }

            /*
            ---------------------------------
            Scan URL
            ---------------------------------
            */

            const baseUrl =
                settings
                .getServiceUrl()
                .replace("/api/v4","");

            const scanUrl =
                `${baseUrl}/main/myapps/` +
                `${process.env.INPUT_APPLICATION_ID}` +
                `/scans/${scanId}`;

            /*
            ---------------------------------
            Markdown summary
            ---------------------------------
            */

            const markdown = `

# HCL AppScan SAST Scan Summary

## ${icon} ${risk}

**Scan ID:** ${scanId}  
**Repository:** ${process.env.GITHUB_REPOSITORY}

---

### Total Vulnerabilities: ${total}

| Critical | High | Medium | Low | Info |
|----------|------|--------|-----|------|
| ${counts.Critical} | ${counts.High} | ${counts.Medium} | ${counts.Low} | ${counts.Informational} |

---

[View scan in AppScan](${scanUrl})

`;

            /*
            ---------------------------------
            Write PR comment file
            ---------------------------------
            */

            fs.writeFileSync(
                "appscan_pr_report.md",
                markdown
            );

            /*
            ---------------------------------
            GitHub Step Summary
            ---------------------------------
            */

            if (
                process.env.GITHUB_STEP_SUMMARY
            ) {

                fs.appendFileSync(
                    process.env.GITHUB_STEP_SUMMARY,
                    markdown
                );

            }

            /*
            ---------------------------------
            Generate SARIF
            ---------------------------------
            */

            const sarif = {

                version: "2.1.0",

                runs: [

                    {

                        tool: {

                            driver: {

                                name:
                                    "HCL AppScan SAST"

                            }

                        },

                        results:

                        result.map(issue => ({

                            ruleId:
                                issue.Severity,

                            level:
                                mapLevel(
                                    issue.Severity
                                ),

                            message: {

                                text:
                                    `${issue.Severity} issue detected`

                            },

                            locations: [

                                {

                                    physicalLocation: {

                                        artifactLocation: {

                                            uri:
                                                "source"

                                        },

                                        region: {

                                            startLine:
                                                1

                                        }

                                    }

                                }

                            ]

                        }))

                    }

                ]

            };

            fs.writeFileSync(

                "appscan-results.sarif",

                JSON.stringify(
                    sarif,
                    null,
                    2
                )

            );

            console.log(
                "Summary + SARIF generated"
            );

            resolve({

                total,
                counts,
                risk

            });

        })

        .catch(reject);

    });

}

/*
-----------------------------------------
Headers
-----------------------------------------
*/
function getHeaders() {

    return {

        Authorization:
            "Bearer " + token,

        Accept:
            "application/json"

    };

}

/*
-----------------------------------------
SARIF severity mapping
-----------------------------------------
*/
function mapLevel(severity) {

    if (
        severity === "Critical" ||
        severity === "High"
    ) {

        return "error";

    }

    if (
        severity === "Medium"
    ) {

        return "warning";

    }

    return "note";

}

export default {

    getScanResults

};
