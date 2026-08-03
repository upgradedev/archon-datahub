"use strict";
const { remediationStream } = require("./runtime-v2.js");
exports.handler = async (event) => {
  try {
    return await remediationStream(event);
  } catch (error) {
    process.stderr.write("[runtime-remediation] approval_stream_failed\n");
    throw error;
  }
};