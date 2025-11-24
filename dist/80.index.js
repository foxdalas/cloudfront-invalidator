"use strict";
exports.id = 80;
exports.ids = [80];
exports.modules = {
  /***/ 2401: /***/ (__unused_webpack_module, exports, __webpack_require__) => {
    var protocolHttp = __webpack_require__(2356);

    function resolveHostHeaderConfig(input) {
      return input;
    }
    const hostHeaderMiddleware = (options) => (next) => async (args) => {
      if (!protocolHttp.HttpRequest.isInstance(args.request)) return next(args);
      const { request } = args;
      const { handlerProtocol = "" } = options.requestHandler.metadata || {};
      if (
        handlerProtocol.indexOf("h2") >= 0 &&
        !request.headers[":authority"]
      ) {
        delete request.headers["host"];
        request.headers[":authority"] =
          request.hostname + (request.port ? ":" + request.port : "");
      } else if (!request.headers["host"]) {
        let host = request.hostname;
        if (request.port != null) host += `:${request.port}`;
        request.headers["host"] = host;
      }
      return next(args);
    };
    const hostHeaderMiddlewareOptions = {
      name: "hostHeaderMiddleware",
      step: "build",
      priority: "low",
      tags: ["HOST"],
      override: true,
    };
    const getHostHeaderPlugin = (options) => ({
      applyToStack: (clientStack) => {
        clientStack.add(
          hostHeaderMiddleware(options),
          hostHeaderMiddlewareOptions,
        );
      },
    });

    exports.getHostHeaderPlugin = getHostHeaderPlugin;
    exports.hostHeaderMiddleware = hostHeaderMiddleware;
    exports.hostHeaderMiddlewareOptions = hostHeaderMiddlewareOptions;
    exports.resolveHostHeaderConfig = resolveHostHeaderConfig;

    /***/
  },

  /***/ 4587: /***/ (__unused_webpack_module, exports) => {
    const loggerMiddleware = () => (next, context) => async (args) => {
      try {
        const response = await next(args);
        const {
          clientName,
          commandName,
          logger,
          dynamoDbDocumentClientOptions = {},
        } = context;
        const {
          overrideInputFilterSensitiveLog,
          overrideOutputFilterSensitiveLog,
        } = dynamoDbDocumentClientOptions;
        const inputFilterSensitiveLog =
          overrideInputFilterSensitiveLog ?? context.inputFilterSensitiveLog;
        const outputFilterSensitiveLog =
          overrideOutputFilterSensitiveLog ?? context.outputFilterSensitiveLog;
        const { $metadata, ...outputWithoutMetadata } = response.output;
        logger?.info?.({
          clientName,
          commandName,
          input: inputFilterSensitiveLog(args.input),
          output: outputFilterSensitiveLog(outputWithoutMetadata),
          metadata: $metadata,
        });
        return response;
      } catch (error) {
        const {
          clientName,
          commandName,
          logger,
          dynamoDbDocumentClientOptions = {},
        } = context;
        const { overrideInputFilterSensitiveLog } =
          dynamoDbDocumentClientOptions;
        const inputFilterSensitiveLog =
          overrideInputFilterSensitiveLog ?? context.inputFilterSensitiveLog;
        logger?.error?.({
          clientName,
          commandName,
          input: inputFilterSensitiveLog(args.input),
          error,
          metadata: error.$metadata,
        });
        throw error;
      }
    };
    const loggerMiddlewareOptions = {
      name: "loggerMiddleware",
      tags: ["LOGGER"],
      step: "initialize",
      override: true,
    };
    const getLoggerPlugin = (options) => ({
      applyToStack: (clientStack) => {
        clientStack.add(loggerMiddleware(), loggerMiddlewareOptions);
      },
    });

    exports.getLoggerPlugin = getLoggerPlugin;
    exports.loggerMiddleware = loggerMiddleware;
    exports.loggerMiddlewareOptions = loggerMiddlewareOptions;

    /***/
  },

  /***/ 5767: /***/ (__unused_webpack_module, exports, __webpack_require__) => {
    var recursionDetectionMiddleware = __webpack_require__(3540);

    const recursionDetectionMiddlewareOptions = {
      step: "build",
      tags: ["RECURSION_DETECTION"],
      name: "recursionDetectionMiddleware",
      override: true,
      priority: "low",
    };

    const getRecursionDetectionPlugin = (options) => ({
      applyToStack: (clientStack) => {
        clientStack.add(
          recursionDetectionMiddleware.recursionDetectionMiddleware(),
          recursionDetectionMiddlewareOptions,
        );
      },
    });

    exports.getRecursionDetectionPlugin = getRecursionDetectionPlugin;
    Object.keys(recursionDetectionMiddleware).forEach(function (k) {
      if (k !== "default" && !Object.prototype.hasOwnProperty.call(exports, k))
        Object.defineProperty(exports, k, {
          enumerable: true,
          get: function () {
            return recursionDetectionMiddleware[k];
          },
        });
    });

    /***/
  },

  /***/ 3540: /***/ (__unused_webpack_module, exports, __webpack_require__) => {
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.recursionDetectionMiddleware = void 0;
    const lambda_invoke_store_1 = __webpack_require__(9320);
    const protocol_http_1 = __webpack_require__(2356);
    const TRACE_ID_HEADER_NAME = "X-Amzn-Trace-Id";
    const ENV_LAMBDA_FUNCTION_NAME = "AWS_LAMBDA_FUNCTION_NAME";
    const ENV_TRACE_ID = "_X_AMZN_TRACE_ID";
    const recursionDetectionMiddleware = () => (next) => async (args) => {
      const { request } = args;
      if (!protocol_http_1.HttpRequest.isInstance(request)) {
        return next(args);
      }
      const traceIdHeader =
        Object.keys(request.headers ?? {}).find(
          (h) => h.toLowerCase() === TRACE_ID_HEADER_NAME.toLowerCase(),
        ) ?? TRACE_ID_HEADER_NAME;
      if (request.headers.hasOwnProperty(traceIdHeader)) {
        return next(args);
      }
      const functionName = process.env[ENV_LAMBDA_FUNCTION_NAME];
      const traceIdFromEnv = process.env[ENV_TRACE_ID];
      const invokeStore =
        await lambda_invoke_store_1.InvokeStore.getInstanceAsync();
      const traceIdFromInvokeStore = invokeStore?.getXRayTraceId();
      const traceId = traceIdFromInvokeStore ?? traceIdFromEnv;
      const nonEmptyString = (str) => typeof str === "string" && str.length > 0;
      if (nonEmptyString(functionName) && nonEmptyString(traceId)) {
        request.headers[TRACE_ID_HEADER_NAME] = traceId;
      }
      return next({
        ...args,
        request,
      });
    };
    exports.recursionDetectionMiddleware = recursionDetectionMiddleware;

    /***/
  },

  /***/ 3084: /***/ (__unused_webpack_module, exports, __webpack_require__) => {
    var configResolver = __webpack_require__(9316);
    var stsRegionDefaultResolver = __webpack_require__(9692);

    const getAwsRegionExtensionConfiguration = (runtimeConfig) => {
      return {
        setRegion(region) {
          runtimeConfig.region = region;
        },
        region() {
          return runtimeConfig.region;
        },
      };
    };
    const resolveAwsRegionExtensionConfiguration = (
      awsRegionExtensionConfiguration,
    ) => {
      return {
        region: awsRegionExtensionConfiguration.region(),
      };
    };

    Object.defineProperty(exports, "NODE_REGION_CONFIG_FILE_OPTIONS", {
      enumerable: true,
      get: function () {
        return configResolver.NODE_REGION_CONFIG_FILE_OPTIONS;
      },
    });
    Object.defineProperty(exports, "NODE_REGION_CONFIG_OPTIONS", {
      enumerable: true,
      get: function () {
        return configResolver.NODE_REGION_CONFIG_OPTIONS;
      },
    });
    Object.defineProperty(exports, "REGION_ENV_NAME", {
      enumerable: true,
      get: function () {
        return configResolver.REGION_ENV_NAME;
      },
    });
    Object.defineProperty(exports, "REGION_INI_NAME", {
      enumerable: true,
      get: function () {
        return configResolver.REGION_INI_NAME;
      },
    });
    Object.defineProperty(exports, "resolveRegionConfig", {
      enumerable: true,
      get: function () {
        return configResolver.resolveRegionConfig;
      },
    });
    exports.getAwsRegionExtensionConfiguration =
      getAwsRegionExtensionConfiguration;
    exports.resolveAwsRegionExtensionConfiguration =
      resolveAwsRegionExtensionConfiguration;
    Object.keys(stsRegionDefaultResolver).forEach(function (k) {
      if (k !== "default" && !Object.prototype.hasOwnProperty.call(exports, k))
        Object.defineProperty(exports, k, {
          enumerable: true,
          get: function () {
            return stsRegionDefaultResolver[k];
          },
        });
    });

    /***/
  },

  /***/ 9692: /***/ (__unused_webpack_module, exports, __webpack_require__) => {
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.warning = void 0;
    exports.stsRegionDefaultResolver = stsRegionDefaultResolver;
    const config_resolver_1 = __webpack_require__(9316);
    const node_config_provider_1 = __webpack_require__(5704);
    function stsRegionDefaultResolver(loaderConfig = {}) {
      return (0, node_config_provider_1.loadConfig)(
        {
          ...config_resolver_1.NODE_REGION_CONFIG_OPTIONS,
          async default() {
            if (!exports.warning.silence) {
              console.warn(
                "@aws-sdk - WARN - default STS region of us-east-1 used. See @aws-sdk/credential-providers README and set a region explicitly.",
              );
            }
            return "us-east-1";
          },
        },
        {
          ...config_resolver_1.NODE_REGION_CONFIG_FILE_OPTIONS,
          ...loaderConfig,
        },
      );
    }
    exports.warning = {
      silence: false,
    };

    /***/
  },

  /***/ 6707: /***/ (__unused_webpack_module, exports, __webpack_require__) => {
    var utilEndpoints = __webpack_require__(9674);
    var urlParser = __webpack_require__(4494);

    const isVirtualHostableS3Bucket = (value, allowSubDomains = false) => {
      if (allowSubDomains) {
        for (const label of value.split(".")) {
          if (!isVirtualHostableS3Bucket(label)) {
            return false;
          }
        }
        return true;
      }
      if (!utilEndpoints.isValidHostLabel(value)) {
        return false;
      }
      if (value.length < 3 || value.length > 63) {
        return false;
      }
      if (value !== value.toLowerCase()) {
        return false;
      }
      if (utilEndpoints.isIpAddress(value)) {
        return false;
      }
      return true;
    };

    const ARN_DELIMITER = ":";
    const RESOURCE_DELIMITER = "/";
    const parseArn = (value) => {
      const segments = value.split(ARN_DELIMITER);
      if (segments.length < 6) return null;
      const [arn, partition, service, region, accountId, ...resourcePath] =
        segments;
      if (
        arn !== "arn" ||
        partition === "" ||
        service === "" ||
        resourcePath.join(ARN_DELIMITER) === ""
      )
        return null;
      const resourceId = resourcePath
        .map((resource) => resource.split(RESOURCE_DELIMITER))
        .flat();
      return {
        partition,
        service,
        region,
        accountId,
        resourceId,
      };
    };

    var partitions = [
      {
        id: "aws",
        outputs: {
          dnsSuffix: "amazonaws.com",
          dualStackDnsSuffix: "api.aws",
          implicitGlobalRegion: "us-east-1",
          name: "aws",
          supportsDualStack: true,
          supportsFIPS: true,
        },
        regionRegex: "^(us|eu|ap|sa|ca|me|af|il|mx)\\-\\w+\\-\\d+$",
        regions: {
          "af-south-1": {
            description: "Africa (Cape Town)",
          },
          "ap-east-1": {
            description: "Asia Pacific (Hong Kong)",
          },
          "ap-east-2": {
            description: "Asia Pacific (Taipei)",
          },
          "ap-northeast-1": {
            description: "Asia Pacific (Tokyo)",
          },
          "ap-northeast-2": {
            description: "Asia Pacific (Seoul)",
          },
          "ap-northeast-3": {
            description: "Asia Pacific (Osaka)",
          },
          "ap-south-1": {
            description: "Asia Pacific (Mumbai)",
          },
          "ap-south-2": {
            description: "Asia Pacific (Hyderabad)",
          },
          "ap-southeast-1": {
            description: "Asia Pacific (Singapore)",
          },
          "ap-southeast-2": {
            description: "Asia Pacific (Sydney)",
          },
          "ap-southeast-3": {
            description: "Asia Pacific (Jakarta)",
          },
          "ap-southeast-4": {
            description: "Asia Pacific (Melbourne)",
          },
          "ap-southeast-5": {
            description: "Asia Pacific (Malaysia)",
          },
          "ap-southeast-6": {
            description: "Asia Pacific (New Zealand)",
          },
          "ap-southeast-7": {
            description: "Asia Pacific (Thailand)",
          },
          "aws-global": {
            description: "aws global region",
          },
          "ca-central-1": {
            description: "Canada (Central)",
          },
          "ca-west-1": {
            description: "Canada West (Calgary)",
          },
          "eu-central-1": {
            description: "Europe (Frankfurt)",
          },
          "eu-central-2": {
            description: "Europe (Zurich)",
          },
          "eu-north-1": {
            description: "Europe (Stockholm)",
          },
          "eu-south-1": {
            description: "Europe (Milan)",
          },
          "eu-south-2": {
            description: "Europe (Spain)",
          },
          "eu-west-1": {
            description: "Europe (Ireland)",
          },
          "eu-west-2": {
            description: "Europe (London)",
          },
          "eu-west-3": {
            description: "Europe (Paris)",
          },
          "il-central-1": {
            description: "Israel (Tel Aviv)",
          },
          "me-central-1": {
            description: "Middle East (UAE)",
          },
          "me-south-1": {
            description: "Middle East (Bahrain)",
          },
          "mx-central-1": {
            description: "Mexico (Central)",
          },
          "sa-east-1": {
            description: "South America (Sao Paulo)",
          },
          "us-east-1": {
            description: "US East (N. Virginia)",
          },
          "us-east-2": {
            description: "US East (Ohio)",
          },
          "us-west-1": {
            description: "US West (N. California)",
          },
          "us-west-2": {
            description: "US West (Oregon)",
          },
        },
      },
      {
        id: "aws-cn",
        outputs: {
          dnsSuffix: "amazonaws.com.cn",
          dualStackDnsSuffix: "api.amazonwebservices.com.cn",
          implicitGlobalRegion: "cn-northwest-1",
          name: "aws-cn",
          supportsDualStack: true,
          supportsFIPS: true,
        },
        regionRegex: "^cn\\-\\w+\\-\\d+$",
        regions: {
          "aws-cn-global": {
            description: "aws-cn global region",
          },
          "cn-north-1": {
            description: "China (Beijing)",
          },
          "cn-northwest-1": {
            description: "China (Ningxia)",
          },
        },
      },
      {
        id: "aws-eusc",
        outputs: {
          dnsSuffix: "amazonaws.eu",
          dualStackDnsSuffix: "api.amazonwebservices.eu",
          implicitGlobalRegion: "eusc-de-east-1",
          name: "aws-eusc",
          supportsDualStack: true,
          supportsFIPS: true,
        },
        regionRegex: "^eusc\\-(de)\\-\\w+\\-\\d+$",
        regions: {
          "eusc-de-east-1": {
            description: "EU (Germany)",
          },
        },
      },
      {
        id: "aws-iso",
        outputs: {
          dnsSuffix: "c2s.ic.gov",
          dualStackDnsSuffix: "api.aws.ic.gov",
          implicitGlobalRegion: "us-iso-east-1",
          name: "aws-iso",
          supportsDualStack: true,
          supportsFIPS: true,
        },
        regionRegex: "^us\\-iso\\-\\w+\\-\\d+$",
        regions: {
          "aws-iso-global": {
            description: "aws-iso global region",
          },
          "us-iso-east-1": {
            description: "US ISO East",
          },
          "us-iso-west-1": {
            description: "US ISO WEST",
          },
        },
      },
      {
        id: "aws-iso-b",
        outputs: {
          dnsSuffix: "sc2s.sgov.gov",
          dualStackDnsSuffix: "api.aws.scloud",
          implicitGlobalRegion: "us-isob-east-1",
          name: "aws-iso-b",
          supportsDualStack: true,
          supportsFIPS: true,
        },
        regionRegex: "^us\\-isob\\-\\w+\\-\\d+$",
        regions: {
          "aws-iso-b-global": {
            description: "aws-iso-b global region",
          },
          "us-isob-east-1": {
            description: "US ISOB East (Ohio)",
          },
          "us-isob-west-1": {
            description: "US ISOB West",
          },
        },
      },
      {
        id: "aws-iso-e",
        outputs: {
          dnsSuffix: "cloud.adc-e.uk",
          dualStackDnsSuffix: "api.cloud-aws.adc-e.uk",
          implicitGlobalRegion: "eu-isoe-west-1",
          name: "aws-iso-e",
          supportsDualStack: true,
          supportsFIPS: true,
        },
        regionRegex: "^eu\\-isoe\\-\\w+\\-\\d+$",
        regions: {
          "aws-iso-e-global": {
            description: "aws-iso-e global region",
          },
          "eu-isoe-west-1": {
            description: "EU ISOE West",
          },
        },
      },
      {
        id: "aws-iso-f",
        outputs: {
          dnsSuffix: "csp.hci.ic.gov",
          dualStackDnsSuffix: "api.aws.hci.ic.gov",
          implicitGlobalRegion: "us-isof-south-1",
          name: "aws-iso-f",
          supportsDualStack: true,
          supportsFIPS: true,
        },
        regionRegex: "^us\\-isof\\-\\w+\\-\\d+$",
        regions: {
          "aws-iso-f-global": {
            description: "aws-iso-f global region",
          },
          "us-isof-east-1": {
            description: "US ISOF EAST",
          },
          "us-isof-south-1": {
            description: "US ISOF SOUTH",
          },
        },
      },
      {
        id: "aws-us-gov",
        outputs: {
          dnsSuffix: "amazonaws.com",
          dualStackDnsSuffix: "api.aws",
          implicitGlobalRegion: "us-gov-west-1",
          name: "aws-us-gov",
          supportsDualStack: true,
          supportsFIPS: true,
        },
        regionRegex: "^us\\-gov\\-\\w+\\-\\d+$",
        regions: {
          "aws-us-gov-global": {
            description: "aws-us-gov global region",
          },
          "us-gov-east-1": {
            description: "AWS GovCloud (US-East)",
          },
          "us-gov-west-1": {
            description: "AWS GovCloud (US-West)",
          },
        },
      },
    ];
    var version = "1.1";
    var partitionsInfo = {
      partitions: partitions,
      version: version,
    };

    let selectedPartitionsInfo = partitionsInfo;
    let selectedUserAgentPrefix = "";
    const partition = (value) => {
      const { partitions } = selectedPartitionsInfo;
      for (const partition of partitions) {
        const { regions, outputs } = partition;
        for (const [region, regionData] of Object.entries(regions)) {
          if (region === value) {
            return {
              ...outputs,
              ...regionData,
            };
          }
        }
      }
      for (const partition of partitions) {
        const { regionRegex, outputs } = partition;
        if (new RegExp(regionRegex).test(value)) {
          return {
            ...outputs,
          };
        }
      }
      const DEFAULT_PARTITION = partitions.find(
        (partition) => partition.id === "aws",
      );
      if (!DEFAULT_PARTITION) {
        throw new Error(
          "Provided region was not found in the partition array or regex," +
            " and default partition with id 'aws' doesn't exist.",
        );
      }
      return {
        ...DEFAULT_PARTITION.outputs,
      };
    };
    const setPartitionInfo = (partitionsInfo, userAgentPrefix = "") => {
      selectedPartitionsInfo = partitionsInfo;
      selectedUserAgentPrefix = userAgentPrefix;
    };
    const useDefaultPartitionInfo = () => {
      setPartitionInfo(partitionsInfo, "");
    };
    const getUserAgentPrefix = () => selectedUserAgentPrefix;

    const awsEndpointFunctions = {
      isVirtualHostableS3Bucket: isVirtualHostableS3Bucket,
      parseArn: parseArn,
      partition: partition,
    };
    utilEndpoints.customEndpointFunctions.aws = awsEndpointFunctions;

    const resolveDefaultAwsRegionalEndpointsConfig = (input) => {
      if (typeof input.endpointProvider !== "function") {
        throw new Error(
          "@aws-sdk/util-endpoint - endpointProvider and endpoint missing in config for this client.",
        );
      }
      const { endpoint } = input;
      if (endpoint === undefined) {
        input.endpoint = async () => {
          return toEndpointV1(
            input.endpointProvider(
              {
                Region:
                  typeof input.region === "function"
                    ? await input.region()
                    : input.region,
                UseDualStack:
                  typeof input.useDualstackEndpoint === "function"
                    ? await input.useDualstackEndpoint()
                    : input.useDualstackEndpoint,
                UseFIPS:
                  typeof input.useFipsEndpoint === "function"
                    ? await input.useFipsEndpoint()
                    : input.useFipsEndpoint,
                Endpoint: undefined,
              },
              { logger: input.logger },
            ),
          );
        };
      }
      return input;
    };
    const toEndpointV1 = (endpoint) => urlParser.parseUrl(endpoint.url);

    Object.defineProperty(exports, "EndpointError", {
      enumerable: true,
      get: function () {
        return utilEndpoints.EndpointError;
      },
    });
    Object.defineProperty(exports, "isIpAddress", {
      enumerable: true,
      get: function () {
        return utilEndpoints.isIpAddress;
      },
    });
    Object.defineProperty(exports, "resolveEndpoint", {
      enumerable: true,
      get: function () {
        return utilEndpoints.resolveEndpoint;
      },
    });
    exports.awsEndpointFunctions = awsEndpointFunctions;
    exports.getUserAgentPrefix = getUserAgentPrefix;
    exports.partition = partition;
    exports.resolveDefaultAwsRegionalEndpointsConfig =
      resolveDefaultAwsRegionalEndpointsConfig;
    exports.setPartitionInfo = setPartitionInfo;
    exports.toEndpointV1 = toEndpointV1;
    exports.useDefaultPartitionInfo = useDefaultPartitionInfo;

    /***/
  },

  /***/ 9955: /***/ (module) => {
    module.exports = /*#__PURE__*/ JSON.parse(
      '{"name":"@aws-sdk/nested-clients","version":"3.936.0","description":"Nested clients for AWS SDK packages.","main":"./dist-cjs/index.js","module":"./dist-es/index.js","types":"./dist-types/index.d.ts","scripts":{"build":"yarn lint && concurrently \'yarn:build:cjs\' \'yarn:build:es\' \'yarn:build:types\'","build:cjs":"node ../../scripts/compilation/inline nested-clients","build:es":"tsc -p tsconfig.es.json","build:include:deps":"lerna run --scope $npm_package_name --include-dependencies build","build:types":"tsc -p tsconfig.types.json","build:types:downlevel":"downlevel-dts dist-types dist-types/ts3.4","clean":"rimraf ./dist-* && rimraf *.tsbuildinfo","lint":"node ../../scripts/validation/submodules-linter.js --pkg nested-clients","test":"yarn g:vitest run","test:watch":"yarn g:vitest watch"},"engines":{"node":">=18.0.0"},"sideEffects":false,"author":{"name":"AWS SDK for JavaScript Team","url":"https://aws.amazon.com/javascript/"},"license":"Apache-2.0","dependencies":{"@aws-crypto/sha256-browser":"5.2.0","@aws-crypto/sha256-js":"5.2.0","@aws-sdk/core":"3.936.0","@aws-sdk/middleware-host-header":"3.936.0","@aws-sdk/middleware-logger":"3.936.0","@aws-sdk/middleware-recursion-detection":"3.936.0","@aws-sdk/middleware-user-agent":"3.936.0","@aws-sdk/region-config-resolver":"3.936.0","@aws-sdk/types":"3.936.0","@aws-sdk/util-endpoints":"3.936.0","@aws-sdk/util-user-agent-browser":"3.936.0","@aws-sdk/util-user-agent-node":"3.936.0","@smithy/config-resolver":"^4.4.3","@smithy/core":"^3.18.5","@smithy/fetch-http-handler":"^5.3.6","@smithy/hash-node":"^4.2.5","@smithy/invalid-dependency":"^4.2.5","@smithy/middleware-content-length":"^4.2.5","@smithy/middleware-endpoint":"^4.3.12","@smithy/middleware-retry":"^4.4.12","@smithy/middleware-serde":"^4.2.6","@smithy/middleware-stack":"^4.2.5","@smithy/node-config-provider":"^4.3.5","@smithy/node-http-handler":"^4.4.5","@smithy/protocol-http":"^5.3.5","@smithy/smithy-client":"^4.9.8","@smithy/types":"^4.9.0","@smithy/url-parser":"^4.2.5","@smithy/util-base64":"^4.3.0","@smithy/util-body-length-browser":"^4.2.0","@smithy/util-body-length-node":"^4.2.1","@smithy/util-defaults-mode-browser":"^4.3.11","@smithy/util-defaults-mode-node":"^4.2.14","@smithy/util-endpoints":"^3.2.5","@smithy/util-middleware":"^4.2.5","@smithy/util-retry":"^4.2.5","@smithy/util-utf8":"^4.2.0","tslib":"^2.6.2"},"devDependencies":{"concurrently":"7.0.0","downlevel-dts":"0.10.1","rimraf":"3.0.2","typescript":"~5.8.3"},"typesVersions":{"<4.0":{"dist-types/*":["dist-types/ts3.4/*"]}},"files":["./signin.d.ts","./signin.js","./sso-oidc.d.ts","./sso-oidc.js","./sts.d.ts","./sts.js","dist-*/**"],"browser":{"./dist-es/submodules/signin/runtimeConfig":"./dist-es/submodules/signin/runtimeConfig.browser","./dist-es/submodules/sso-oidc/runtimeConfig":"./dist-es/submodules/sso-oidc/runtimeConfig.browser","./dist-es/submodules/sts/runtimeConfig":"./dist-es/submodules/sts/runtimeConfig.browser"},"react-native":{},"homepage":"https://github.com/aws/aws-sdk-js-v3/tree/main/packages/nested-clients","repository":{"type":"git","url":"https://github.com/aws/aws-sdk-js-v3.git","directory":"packages/nested-clients"},"exports":{"./package.json":"./package.json","./sso-oidc":{"types":"./dist-types/submodules/sso-oidc/index.d.ts","module":"./dist-es/submodules/sso-oidc/index.js","node":"./dist-cjs/submodules/sso-oidc/index.js","import":"./dist-es/submodules/sso-oidc/index.js","require":"./dist-cjs/submodules/sso-oidc/index.js"},"./sts":{"types":"./dist-types/submodules/sts/index.d.ts","module":"./dist-es/submodules/sts/index.js","node":"./dist-cjs/submodules/sts/index.js","import":"./dist-es/submodules/sts/index.js","require":"./dist-cjs/submodules/sts/index.js"},"./signin":{"types":"./dist-types/submodules/signin/index.d.ts","module":"./dist-es/submodules/signin/index.js","node":"./dist-cjs/submodules/signin/index.js","import":"./dist-es/submodules/signin/index.js","require":"./dist-cjs/submodules/signin/index.js"}}}',
    );

    /***/
  },
};
//# sourceMappingURL=80.index.js.map
