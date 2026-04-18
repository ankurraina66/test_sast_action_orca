/*
Copyright 2022, 2024 HCL America
*/

import got from 'got';
import * as constants from './constants.js';
import resultProcessor from './resultProcessor.js';
import settings from './settings.js';
import utils from './utils.js';
import fs from 'fs';

let token = null;

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

            token =
                JSON.parse(res.body).Token;

            resolve();

        })

        .catch(reject);

    });

}

function getScanResults(scanId, prContext = {}) {

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
            getIssues(scanId, prContext = {})
        )

        .then(resolve)

        .catch(reject);

    });

}

async function getSastScanDetails(scanId) {
console.log("---------------------- inside  getSastScanDetails->", scanId);
   const url =
    settings.getServiceUrl()
    + "/api/v4/Scans/Sast/"
    + scanId;

	console.log(">>>>>>>>>>>>>>>>>>>>>>>>>DEBUG: Calling API ->", url);

    try {
	console.log("---------------------- inside  getSastScanDetails-> executing api call");
        const res =
            await got.get(url, {

                headers: {

                    Authorization:
                        "Bearer " + token,

                    Accept:
                        "application/json"
                }
            });

        return JSON.parse(res.body);

    } catch (e) {

        console.log(
            "Failed to fetch SAST scan details:",
            e.message
        );

        return null;
    }
}
async function getIssues(scanId, prContext = {}) {

    return new Promise((resolve, reject) => {

        const query =
            "?applyPolicies=None" +
            "&%24filter=Status%20eq%20%27Open%27" +
            "%20or%20Status%20eq%20%27New%27" +
            "%20or%20Status%20eq%20%27Reopened%27" +
            "%20or%20Status%20eq%20%27InProgress%27";

        const url =
            settings.getServiceUrl() +
            constants.API_ISSUES +
            scanId +
            query;

        got.get(url, {

            headers: {

                Authorization:
                    "Bearer " + token,

                Accept:
                    "application/json"

            }

        })

        .then(res => {

            const json =
                JSON.parse(res.body);

            return json.Items;

        })

        .then(async issues => {

            issues =
                issues || [];

            const counts = {

                Critical: 0,
                High: 0,
                Medium: 0,
                Low: 0,
                Informational: 0

            };

            issues.forEach(i => {

                if (
                    counts[i.Severity] !== undefined
                ) {

                    counts[i.Severity]++;

                }

            });

            const total =
                Object.values(counts)
                .reduce(
                    (a,b)=>a+b,
                    0
                );

            let risk = "No Risk";
            let icon = "⚪";

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
                `${baseUrl}/main/myapps/${process.env.INPUT_APPLICATION_ID}/scans/${scanId}`;
			const applicationId =   process.env.INPUT_APPLICATION_ID;
		    let appName =
    applicationId;

try {

    const scanDetails =
        await getSastScanDetails(scanId);

    if(scanDetails && scanDetails.AppName){

        appName =
            scanDetails.AppName;
    }

} catch (e) {

    console.log(
        "Failed to fetch AppName from scan details"
    );

}

			const appUrl =`${baseUrl}/main/myapps/${applicationId}`;

            const scanTime =
                new Date()
                .toISOString()
                .replace("T"," ")
                .substring(0,19);
				
			const isPR =
    prContext.isPR || false;

const prNumber =
    prContext.prNumber || "";

const branchName =
    prContext.branchName || "";

const repoName =
    prContext.repoName || process.env.GITHUB_REPOSITORY;

const commitSha =
    prContext.commitSha
    ? prContext.commitSha.substring(0,7)
    : "";

			const scanLabel = isPR ? "SAST PR Scan Summary" : "SAST Scan Summary";

			console.log("?????????????????????????----------------------DEBUG: Final AppName used in summary ->", appName);

			const prSection =
			    isPR
			    ? `
			
			### Pull Request Information
			
			| Field | Value |
			|------|------|
			| PR Number | #${prNumber} |
			| Branch | ${branchName} |
			| Commit | ${commitSha} |
			
			---`
			    : "";

	            const md = `

#  HCL AppScan ${scanLabel}

${prSection}

### Scan Information

| Field | Value |
|------|-------|
| Scan Type | SAST |
| Scan ID | [${scanId}](${scanUrl}) |
| Application Name | [${appName}](${appUrl}) |
| Repository | ${process.env.GITHUB_REPOSITORY} |
| Scan Time | ${scanTime} |

---

## Total Vulnerabilities: ${total}

| Critical | High | Medium | Low | Info |
|----------|------|--------|-----|------|
| ${counts.Critical} | ${counts.High} | ${counts.Medium} | ${counts.Low} | ${counts.Informational} |

---

[View scan details in AppScan](${scanUrl})

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

                        issues.map(i => ({

                            ruleId:
                                i.IssueType || "AppScanIssue",

                            level:
                                mapLevel(
                                    i.Severity
                                ),

                            message: {

                                text:
                                    i.IssueType

                            },

                            locations: [

                                {

                                    physicalLocation: {

                                        artifactLocation: {

                                            uri:
                                                i.Location || "source"

                                        },

                                        region: {

                                            startLine: 1

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

            resolve({
                total,
                counts
            });

        })

        .catch(reject);

    });

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
