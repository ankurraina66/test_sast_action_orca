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
            getIssues(scanId, prContext)
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
	console.log(">>>>>>>>>>>>>>>>>>>>>PR CONTEXT RECEIVED:", prContext);
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
			let executionId = "";

try {

    const scanDetails =
        await getSastScanDetails(scanId);

   if(scanDetails){

    appName =
        scanDetails.AppName || appName;

    executionId =
        scanDetails.ExecutionId || "";

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

			const prUrl =
 `https://github.com/${repoName}/pull/${prNumber}`;

const branchUrl =
 `https://github.com/${repoName}/tree/${branchName}`;

const commitUrl =
 `https://github.com/${repoName}/commit/${prContext.commitSha}`;
const issueBaseUrl =
 `${baseUrl}/main/myapps/${applicationId}/scans/${scanId}/scanIssues?executionId=${executionId}`;

const prSection =
    isPR
    ? `

## Pull Request Information

| Field | Value |
|------|------|
| PR Number | [#${prNumber}](${prUrl}) |
| Branch | [${branchName}](${branchUrl}) |
| Commit | [${commitSha}](${commitUrl}) |

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

			/*
			 ADD HTML REPORT GENERATION HERE
			*/
			
			const htmlReport =
			    generateHtmlReport(
			        issues,
			        counts,
			        scanUrl,
			        appName,
					issueBaseUrl
			    );
			
			fs.writeFileSync(
			    "appscan-report.html",
			    htmlReport
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

function generateHtmlReport(
    issues,
    counts,
    scanUrl,
    appName,
	issueBaseUrl
){

return `

<html>

<head>

<style>

body {
 font-family: Arial;
 margin: 40px;
}

table {
 border-collapse: collapse;
 width: 100%;
 margin-bottom: 30px;
}

th, td {
 border: 1px solid #ddd;
 padding: 8px;
}

th {
 background: #f5f5f5;
}

.sev-critical { color: red; }
.sev-high { color: darkred; }
.sev-medium { color: orange; }
.sev-low { color: green; }

</style>

</head>

<body>

<h1>HCL AppScan SAST Report</h1>

<h2>Application: ${appName}</h2>

<h3>Summary</h3>

<table>

<tr>

<th>Critical</th>
<th>High</th>
<th>Medium</th>
<th>Low</th>
<th>Info</th>

</tr>

<tr>

<td>${counts.Critical}</td>
<td>${counts.High}</td>
<td>${counts.Medium}</td>
<td>${counts.Low}</td>
<td>${counts.Informational}</td>

</tr>

</table>

<h3>Issues</h3>

<table>

<tr>

<th>Severity</th>
<th>Issue type</th>
<th>Location</th>
<th>Line</th>
<th>How to fix</th>

</tr>

${issues.map(i => `

<tr>

<td class="sev-${i.Severity.toLowerCase()}">

${i.Severity}

</td>

<td>

${i.IssueType}

</td>

<td>

${i.Location || ""}

</td>

<td>

${(i.Location || "").split(":").pop()}

</td>

<td>

<a href="${issueBaseUrl}&filterIds=${i.Id}" target="_blank">

View Fix in AppScan

</a>

</td>

</tr>

`).join("")}

</table>

<p>

Full scan:

<a href="${scanUrl}">

View in AppScan

</a>

</p>

</body>

</html>

`;
}

export default {

    getScanResults

};
