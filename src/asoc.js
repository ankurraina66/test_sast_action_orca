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

let token = null

function login(key, secret) {
    return new Promise((resolve, reject) => {

        if (!key || !secret) {
            reject("Missing API key/secret");
            return;
        }

        const url =
            settings.getServiceUrl() +
            constants.API_LOGIN;

        got.post(
            url,
            {
                json: {
                    keyId: key,
                    keySecret: secret,
                    clientType: utils.getClientType()
                }
            }
        )
        .then(res => {

            const body =
                JSON.parse(res.body);

            token =
                body.Token;

            resolve();

        })
        .catch(err => reject(err));

    });
}

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
        .then(() => {

            return resolve(
                getNonCompliantIssues(scanId)
            );

        })
        .catch(reject);

    });

}

function getNonCompliantIssues(scanId) {

    return new Promise((resolve, reject) => {

        const fs =
            require("fs");

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

        got.get(
            url,
            {
                headers: getHeaders()
            }
        )
        .then(res => {

            const json =
                JSON.parse(res.body);

            return resultProcessor
                .processResults(json.Items);

        })
        .then(result => {

            if (!result || result.length === 0) {

                console.log(
                    "No findings returned from AppScan"
                );

            }

            const counts = {

                Critical: 0,
                High: 0,
                Medium: 0,
                Low: 0,
                Informational: 0

            };

            result.forEach(i => {

                if (
                    counts[i.Severity] !== undefined
                ) {

                    counts[i.Severity] += i.Count;

                }

            });

            const total =
                Object.values(counts)
                .reduce(
                    (a,b)=>a+b,
                    0
                );

            let risk =
                "No Risk";

            let icon =
                "⚪";

            if (counts.Critical > 0) {

                risk = "Critical Risk";
                icon = "🔴";

            }
            else if (counts.High > 0) {

                risk = "High Risk";
                icon = "🔴";

            }
            else if (counts.Medium > 0) {

                risk = "Medium Risk";
                icon = "🟡";

            }
            else if (counts.Low > 0) {

                risk = "Low Risk";
                icon = "🟢";

            }

            const baseUrl =
                settings.getServiceUrl()
                .replace("/api/v4","");

            const scanUrl =
                `${baseUrl}/main/myapps/` +
                `${process.env.INPUT_APPLICATION_ID}` +
                `/scans/${scanId}`;

            const md = `
# HCL AppScan SAST Scan Summary

## ${icon} ${risk}

**Scan ID:** ${scanId}  
**Repository:** ${process.env.GITHUB_REPOSITORY}

---

### Total Vulnerabilities: ${total}

| Critical | High | Medium | Low | Info |
|---------|------|--------|-----|------|
| ${counts.Critical} |
${counts.High} |
${counts.Medium} |
${counts.Low} |
${counts.Informational} |

---

[View scan in AppScan](${scanUrl})
`;

            fs.writeFileSync(
                "appscan_pr_report.md",
                md
            );

            if (
                process.env.GITHUB_STEP_SUMMARY
            ) {

                fs.appendFileSync(

                    process.env.GITHUB_STEP_SUMMARY,
                    md

                );

            }

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

                        result.map(i => ({

                            ruleId:
                                i.Severity,

                            level:
                                mapLevel(
                                    i.Severity
                                ),

                            message: {

                                text:
                                    `${i.Severity} issue detected`

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
                "Summary and SARIF generated"
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

function getHeaders() {

    return {

        Authorization:
            "Bearer " + token,

        Accept:
            "application/json"

    };

}

function mapLevel(sev) {

    if (
        sev === "Critical" ||
        sev === "High"
    ) return "error";

    if (
        sev === "Medium"
    ) return "warning";

    return "note";

}

export default {

    getScanResults

};
