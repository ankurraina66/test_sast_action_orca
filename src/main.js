/*
Copyright 2022, 2026 HCL America, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

import * as core from '@actions/core';
import * as constants from './constants.js';
import client from './client.js';
import saclientutil from './saclientutil.js';
import asoc from './asoc.js';
import settings from './settings.js';

/*
 detect PR context
*/
const isPR =
    process.env.GITHUB_EVENT_NAME === "pull_request";

core.info(`GitHub Event: ${process.env.GITHUB_EVENT_NAME}`);

if(isPR){

    core.info("Running SAST scan for Pull Request");

    core.info(`Repository: ${process.env.GITHUB_REPOSITORY}`);

    core.info(`Branch: ${process.env.GITHUB_HEAD_REF}`);

}
else{

    core.info("Running SAST scan for Push/Manual trigger");

}

/*
 begin scan workflow
*/
core.info(constants.DOWNLOADING_CLIENT);

saclientutil.downloadClient()

.then(() => {

    core.info(constants.GENERATING_IRX);

    return client.generateIrx();

})

.then(() => {

    core.info(constants.AUTHENTICATE_ASOC);

    return client.login();

})

.then(() => {

    core.info(constants.SUBMITTING_IRX);

    return client.runAnalysis();

})

.then((scanId) => {

    return new Promise((resolve, reject) => {

        core.info(constants.IRX_SUBMIT_SUCCESS);

        core.info(`Scan ID: ${scanId}`);

        core.info(`Scan URL: ${settings.getScanUrl(scanId)}`);

        /*
         PR metadata logging
        */
        if(isPR){

            core.info(`PR scan detected`);

            core.info(`PR branch: ${process.env.GITHUB_HEAD_REF}`);

        }

        /*
         skip waiting if not requested
        */
        if(process.env.INPUT_WAIT_FOR_ANALYSIS !== 'true') {

            core.info("wait_for_analysis=false → skipping result polling");

            return resolve();

        }

        core.info(constants.WAIT_FOR_ANALYSIS);

        client.waitForAnalysis(scanId)

        .then((timedOut) => {

            if(timedOut) {

                core.warning(constants.ANALYSIS_TIMEOUT);

                return resolve();

            }

            core.info(constants.GETTING_RESULTS);

            /*
             generate build summary + SARIF

             works for BOTH the push and PR

            */
            return asoc.getScanResults(scanId);

        })

        .then((results) => {

            if(results) {

                core.info("Scan results summary:");

                core.info(JSON.stringify(results, null, 2));

                core.info(constants.ANALYSIS_SUCCESS);

            }

            resolve();

        })

        .catch((error) => {

            return reject(error);

        });

    });

})

.catch((error) => {

    core.setFailed(error);

<<<<<<< HEAD
});
=======
});
>>>>>>> 53044b01849dc9c87e5f29a80ce1e125f1fbc1b2
