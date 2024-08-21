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

        // Split the comma-separated string into an array
        let paths;
        try {
            paths = pathsInput.split(",").map(path => path.trim());
        } catch (error) {
            throw new Error(
                "Failed to parse paths input. Ensure it is a valid comma-separated string.",
            );
        }

        // Ensure all paths are correctly formatted
        paths = paths.map((path) => (path.startsWith("/") ? path : `/${path}`));

        console.log(`Invalidation paths: ${JSON.stringify(paths)}`);

        for (const distributionId of distributionIds) {
            await createInvalidation(distributionId, paths, waitForInvalidation);
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
        console.warn("No ARN found with the provided tags");
        process.exit(0); // Exit the script gracefully
    }

    // Extract distribution IDs from the ARNs
    return data.ResourceTagMappingList.map((mapping) => {
        const arn = mapping.ResourceARN;
        return arn.split("/").pop();
    });
}

async function createInvalidation(distributionId, paths, waitForInvalidation) {
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

    try {
        const command = new CreateInvalidationCommand(params);
        const response = await client.send(command);
        const invalidationId = response.Invalidation.Id;

        console.log(
            `Posted CloudFront invalidation for paths: ${JSON.stringify(paths)} on distribution: ${distributionId}`,
        );

        if (waitForInvalidation) {
            console.log(`Waiting for invalidation ${invalidationId} to complete...`);
            const waiterParams = {
                client,
                maxWaitTime: 300, // Maximum wait time in seconds
            };
            await waitUntilInvalidationCompleted(
                { ...waiterParams },
                { DistributionId: distributionId, Id: invalidationId },
            );
            console.log(`Invalidation ${invalidationId} completed.`);
        } else {
            console.log(`Invalidation ${invalidationId} initiated.`);
        }
    } catch (error) {
        console.error(
            `Failed to invalidate paths: ${JSON.stringify(paths)} on distribution: ${distributionId}`,
            error,
        );
        throw error;
    }
}

run();
