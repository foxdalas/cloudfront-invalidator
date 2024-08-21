const core = require("@actions/core");
import {
  ResourceGroupsTaggingAPIClient,
  GetResourcesCommand,
} from "@aws-sdk/client-resource-groups-tagging-api";
import {
  CloudFrontClient,
  CreateInvalidationCommand,
} from "@aws-sdk/client-cloudfront";

async function run() {
  try {
    const distributionIds = await getDistributionIdsByTag();
    const pathsInput = core.getInput("paths");

    // Parse JSON string to array
    let paths;
    try {
      paths = JSON.parse(pathsInput);
    } catch (error) {
      throw new Error(
        "Failed to parse paths input as JSON. Ensure it is a valid JSON array.",
      );
    }

    // Ensure all paths are correctly formatted
    paths = paths
      .map((path) => path.trim())
      .map((path) => (path.startsWith("/") ? path : `/${path}`));

    console.log(`Invalidation paths: ${JSON.stringify(paths)}`);

    for (const distributionId of distributionIds) {
      for (const path of paths) {
        await createInvalidation(distributionId, path);
      }
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
    throw new Error("No ARN found with the provided tags");
  }

  // Extract distribution IDs from the ARNs
  return data.ResourceTagMappingList.map((mapping) => {
    const arn = mapping.ResourceARN;
    return arn.split("/").pop();
  });
}

async function createInvalidation(distributionId, path) {
  const client = new CloudFrontClient();
  const params = {
    DistributionId: distributionId,
    InvalidationBatch: {
      CallerReference: String(new Date().getTime()),
      Paths: {
        Quantity: 1,
        Items: [path],
      },
    },
  };

  try {
    const command = new CreateInvalidationCommand(params);
    const response = await client.send(command);
    console.log(
      `Posted CloudFront invalidation for path: ${path} on distribution: ${distributionId}`,
    );
    console.log("Response:", response);
  } catch (error) {
    console.error(
      `Failed to invalidate path: ${path} on distribution: ${distributionId}`,
      error,
    );
    throw error;
  }
}

run();
