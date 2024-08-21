const core = require('@actions/core');
const AWS = require('aws-sdk');
const { CloudFrontClient, CreateInvalidationCommand } = require('@aws-sdk/client-cloudfront');

async function run() {
    try {
        const distributionId = await getDistributionIdByTag();
        const paths = core.getInput('paths').split(',').map(path => path.trim());

        for (const path of paths) {
            await createInvalidation(distributionId, path);
        }
    } catch (error) {
        core.setFailed(error.message);
    }
}

async function getDistributionIdByTag() {
    const resourceTaggingAPI = new AWS.ResourceGroupsTaggingAPI({ region: 'us-east-1' });
    const params = {
        ResourceTypeFilters: ['cloudfront:distribution'],
        TagFilters: [{ Key: core.getInput('tag_key'), Values: [core.getInput('tag_value')] }]
    };

    const data = await resourceTaggingAPI.getResources(params).promise();
    const arn = data.ResourceTagMappingList.length ? data.ResourceTagMappingList[0].ResourceARN : null;

    if (!arn) {
        throw new Error('No ARN found with the provided tags');
    }

    return arn.split('/').pop();
}

async function createInvalidation(distributionId, path) {
    const client = new CloudFrontClient();
    const params = {
        DistributionId: distributionId,
        InvalidationBatch: {
            CallerReference: String(new Date().getTime()),
            Paths: {
                Quantity: 1,
                Items: [path]
            }
        }
    };

    const command = new CreateInvalidationCommand(params);
    const response = await client.send(command);

    console.log(`Posted CloudFront invalidation for path: ${path}`);
    console.log('Response:', response);
}

run();
