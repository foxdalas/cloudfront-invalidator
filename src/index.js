const core = require("@actions/core");
import {
  ResourceGroupsTaggingAPIClient,
  GetResourcesCommand,
} from "@aws-sdk/client-resource-groups-tagging-api";
import {
  CloudFrontClient,
  CreateInvalidationCommand,
  waitUntilInvalidationCompleted,
} from "@aws-sdk/client-cloudfront";

async function run() {
  try {
    const distributionIds = await getDistributionIdsByTag();
    const pathsInput = core.getInput("paths");
    const waitForInvalidation = core.getInput("wait") === "true";
    const maxWaitTime = core.getInput("timeout");

    // Split the comma-separated string into an array
    let paths;
    try {
      paths = pathsInput.split(",").map((path) => path.trim());
    } catch (error) {
      throw new Error(
        "Failed to parse paths input. Ensure it is a valid comma-separated string.",
      );
    }

    // Ensure all paths are correctly formatted
    paths = paths.map((path) => (path.startsWith("/") ? path : `/${path}`));

    core.info(`Invalidation paths: ${JSON.stringify(paths)}`);

    for (const distributionId of distributionIds) {
      await createInvalidation(
        distributionId,
        paths,
        waitForInvalidation,
        maxWaitTime,
      );
    }
  } catch (error) {
    core.setFailed(error.message);
  }
}

async function getDistributionIdsByTag() {
  const client = new ResourceGroupsTaggingAPIClient({ region: "us-east-1" });
  const command = new GetResourcesCommand({
    ResourceTypeFilters: ["cloudfront:distribution"],
    TagFilters: [
      { Key: core.getInput("tag_key"), Values: [core.getInput("tag_value")] },
    ],
  });

  const data = await client.send(command);

  if (!data.ResourceTagMappingList.length) {
    core.warning("No ARN found with the provided tags");
    process.exit(0); // Exit the script gracefully
  }

  // Extract distribution IDs from the ARNs
  return data.ResourceTagMappingList.map((mapping) => {
    const arn = mapping.ResourceARN;
    return arn.split("/").pop();
  });
}

async function createInvalidation(
  distributionId,
  paths,
  waitForInvalidation,
  maxWaitTime,
) {
  const client = new CloudFrontClient();
  const params = {
    DistributionId: distributionId,
    InvalidationBatch: {
      CallerReference: String(new Date().getTime()),
      Paths: {
        Quantity: paths.length,
        Items: paths,
      },
    },
  };

  let attempts = 0;
  let maxAttempts = 12; // 12 attempts with delay increasing up to 120 seconds
  let delay = 10000; // Initial delay of 10 seconds

  while (attempts < maxAttempts) {
    try {
      attempts++;
      const command = new CreateInvalidationCommand(params);
      const response = await client.send(command);
      const invalidationId = response.Invalidation.Id;

      core.info(
        `Posted CloudFront invalidation for paths: ${JSON.stringify(paths)} on distribution: ${distributionId}`,
      );

      if (waitForInvalidation) {
        core.info(`Waiting for invalidation ${invalidationId} to complete...`);
        const waiterParams = {
          client,
          maxWaitTime: maxWaitTime, // Maximum wait time in seconds
        };
        await waitUntilInvalidationCompleted(
          { ...waiterParams },
          { DistributionId: distributionId, Id: invalidationId },
        );
        core.info(`Invalidation ${invalidationId} completed.`);
      } else {
        core.info(`Invalidation ${invalidationId} initiated.`);
      }
      return; // Exit the loop if the request succeeds
    } catch (error) {
      if (error.Code === "Throttling") {
        core.warning(
          `Throttling detected. Attempt ${attempts} of ${maxAttempts}. Retrying in ${delay / 1000} seconds...`,
        );
        await new Promise((resolve) => setTimeout(resolve, delay));
        delay = Math.min(delay + 10000, 120000); // Increase delay by 10 seconds, max 120 seconds
      } else {
        core.error(
          `Failed to invalidate paths: ${JSON.stringify(paths)} on distribution: ${distributionId}`,
          error,
        );
        throw error;
      }
    }
  }
  throw new Error(
    `Failed to create invalidation after ${attempts} attempts due to throttling.`,
  );
}

run();
