"use strict";
exports.id = 652;
exports.ids = [652];
exports.modules = {
  /***/ 9722: /***/ (__unused_webpack_module, exports, __webpack_require__) => {
    var protocolHttp = __webpack_require__(2356);
    var core = __webpack_require__(402);
    var propertyProvider = __webpack_require__(1238);
    var client = __webpack_require__(2826);
    var signatureV4 = __webpack_require__(5118);
    var cbor = __webpack_require__(4645);
    var schema = __webpack_require__(6890);
    var smithyClient = __webpack_require__(1411);
    var protocols = __webpack_require__(3422);
    var serde = __webpack_require__(2430);
    var utilBase64 = __webpack_require__(8385);
    var utilUtf8 = __webpack_require__(1577);
    var xmlBuilder = __webpack_require__(7660);

    const state = {
      warningEmitted: false,
    };
    const emitWarningIfUnsupportedVersion = (version) => {
      if (
        version &&
        !state.warningEmitted &&
        parseInt(version.substring(1, version.indexOf("."))) < 18
      ) {
        state.warningEmitted = true;
        process.emitWarning(`NodeDeprecationWarning: The AWS SDK for JavaScript (v3) will
no longer support Node.js 16.x on January 6, 2025.

To continue receiving updates to AWS services, bug fixes, and security
updates please upgrade to a supported Node.js LTS version.

More information can be found at: https://a.co/74kJMmI`);
      }
    };

    function setCredentialFeature(credentials, feature, value) {
      if (!credentials.$source) {
        credentials.$source = {};
      }
      credentials.$source[feature] = value;
      return credentials;
    }

    function setFeature(context, feature, value) {
      if (!context.__aws_sdk_context) {
        context.__aws_sdk_context = {
          features: {},
        };
      } else if (!context.__aws_sdk_context.features) {
        context.__aws_sdk_context.features = {};
      }
      context.__aws_sdk_context.features[feature] = value;
    }

    function setTokenFeature(token, feature, value) {
      if (!token.$source) {
        token.$source = {};
      }
      token.$source[feature] = value;
      return token;
    }

    const getDateHeader = (response) =>
      protocolHttp.HttpResponse.isInstance(response)
        ? (response.headers?.date ?? response.headers?.Date)
        : undefined;

    const getSkewCorrectedDate = (systemClockOffset) =>
      new Date(Date.now() + systemClockOffset);

    const isClockSkewed = (clockTime, systemClockOffset) =>
      Math.abs(getSkewCorrectedDate(systemClockOffset).getTime() - clockTime) >=
      300000;

    const getUpdatedSystemClockOffset = (
      clockTime,
      currentSystemClockOffset,
    ) => {
      const clockTimeInMs = Date.parse(clockTime);
      if (isClockSkewed(clockTimeInMs, currentSystemClockOffset)) {
        return clockTimeInMs - Date.now();
      }
      return currentSystemClockOffset;
    };

    const throwSigningPropertyError = (name, property) => {
      if (!property) {
        throw new Error(
          `Property \`${name}\` is not resolved for AWS SDK SigV4Auth`,
        );
      }
      return property;
    };
    const validateSigningProperties = async (signingProperties) => {
      const context = throwSigningPropertyError(
        "context",
        signingProperties.context,
      );
      const config = throwSigningPropertyError(
        "config",
        signingProperties.config,
      );
      const authScheme = context.endpointV2?.properties?.authSchemes?.[0];
      const signerFunction = throwSigningPropertyError("signer", config.signer);
      const signer = await signerFunction(authScheme);
      const signingRegion = signingProperties?.signingRegion;
      const signingRegionSet = signingProperties?.signingRegionSet;
      const signingName = signingProperties?.signingName;
      return {
        config,
        signer,
        signingRegion,
        signingRegionSet,
        signingName,
      };
    };
    class AwsSdkSigV4Signer {
      async sign(httpRequest, identity, signingProperties) {
        if (!protocolHttp.HttpRequest.isInstance(httpRequest)) {
          throw new Error(
            "The request is not an instance of `HttpRequest` and cannot be signed",
          );
        }
        const validatedProps =
          await validateSigningProperties(signingProperties);
        const { config, signer } = validatedProps;
        let { signingRegion, signingName } = validatedProps;
        const handlerExecutionContext = signingProperties.context;
        if (handlerExecutionContext?.authSchemes?.length ?? 0 > 1) {
          const [first, second] = handlerExecutionContext.authSchemes;
          if (first?.name === "sigv4a" && second?.name === "sigv4") {
            signingRegion = second?.signingRegion ?? signingRegion;
            signingName = second?.signingName ?? signingName;
          }
        }
        const signedRequest = await signer.sign(httpRequest, {
          signingDate: getSkewCorrectedDate(config.systemClockOffset),
          signingRegion: signingRegion,
          signingService: signingName,
        });
        return signedRequest;
      }
      errorHandler(signingProperties) {
        return (error) => {
          const serverTime = error.ServerTime ?? getDateHeader(error.$response);
          if (serverTime) {
            const config = throwSigningPropertyError(
              "config",
              signingProperties.config,
            );
            const initialSystemClockOffset = config.systemClockOffset;
            config.systemClockOffset = getUpdatedSystemClockOffset(
              serverTime,
              config.systemClockOffset,
            );
            const clockSkewCorrected =
              config.systemClockOffset !== initialSystemClockOffset;
            if (clockSkewCorrected && error.$metadata) {
              error.$metadata.clockSkewCorrected = true;
            }
          }
          throw error;
        };
      }
      successHandler(httpResponse, signingProperties) {
        const dateHeader = getDateHeader(httpResponse);
        if (dateHeader) {
          const config = throwSigningPropertyError(
            "config",
            signingProperties.config,
          );
          config.systemClockOffset = getUpdatedSystemClockOffset(
            dateHeader,
            config.systemClockOffset,
          );
        }
      }
    }
    const AWSSDKSigV4Signer = AwsSdkSigV4Signer;

    class AwsSdkSigV4ASigner extends AwsSdkSigV4Signer {
      async sign(httpRequest, identity, signingProperties) {
        if (!protocolHttp.HttpRequest.isInstance(httpRequest)) {
          throw new Error(
            "The request is not an instance of `HttpRequest` and cannot be signed",
          );
        }
        const { config, signer, signingRegion, signingRegionSet, signingName } =
          await validateSigningProperties(signingProperties);
        const configResolvedSigningRegionSet =
          await config.sigv4aSigningRegionSet?.();
        const multiRegionOverride = (
          configResolvedSigningRegionSet ??
          signingRegionSet ?? [signingRegion]
        ).join(",");
        const signedRequest = await signer.sign(httpRequest, {
          signingDate: getSkewCorrectedDate(config.systemClockOffset),
          signingRegion: multiRegionOverride,
          signingService: signingName,
        });
        return signedRequest;
      }
    }

    const getArrayForCommaSeparatedString = (str) =>
      typeof str === "string" && str.length > 0
        ? str.split(",").map((item) => item.trim())
        : [];

    const getBearerTokenEnvKey = (signingName) =>
      `AWS_BEARER_TOKEN_${signingName.replace(/[\s-]/g, "_").toUpperCase()}`;

    const NODE_AUTH_SCHEME_PREFERENCE_ENV_KEY = "AWS_AUTH_SCHEME_PREFERENCE";
    const NODE_AUTH_SCHEME_PREFERENCE_CONFIG_KEY = "auth_scheme_preference";
    const NODE_AUTH_SCHEME_PREFERENCE_OPTIONS = {
      environmentVariableSelector: (env, options) => {
        if (options?.signingName) {
          const bearerTokenKey = getBearerTokenEnvKey(options.signingName);
          if (bearerTokenKey in env) return ["httpBearerAuth"];
        }
        if (!(NODE_AUTH_SCHEME_PREFERENCE_ENV_KEY in env)) return undefined;
        return getArrayForCommaSeparatedString(
          env[NODE_AUTH_SCHEME_PREFERENCE_ENV_KEY],
        );
      },
      configFileSelector: (profile) => {
        if (!(NODE_AUTH_SCHEME_PREFERENCE_CONFIG_KEY in profile))
          return undefined;
        return getArrayForCommaSeparatedString(
          profile[NODE_AUTH_SCHEME_PREFERENCE_CONFIG_KEY],
        );
      },
      default: [],
    };

    const resolveAwsSdkSigV4AConfig = (config) => {
      config.sigv4aSigningRegionSet = core.normalizeProvider(
        config.sigv4aSigningRegionSet,
      );
      return config;
    };
    const NODE_SIGV4A_CONFIG_OPTIONS = {
      environmentVariableSelector(env) {
        if (env.AWS_SIGV4A_SIGNING_REGION_SET) {
          return env.AWS_SIGV4A_SIGNING_REGION_SET.split(",").map((_) =>
            _.trim(),
          );
        }
        throw new propertyProvider.ProviderError(
          "AWS_SIGV4A_SIGNING_REGION_SET not set in env.",
          {
            tryNextLink: true,
          },
        );
      },
      configFileSelector(profile) {
        if (profile.sigv4a_signing_region_set) {
          return (profile.sigv4a_signing_region_set ?? "")
            .split(",")
            .map((_) => _.trim());
        }
        throw new propertyProvider.ProviderError(
          "sigv4a_signing_region_set not set in profile.",
          {
            tryNextLink: true,
          },
        );
      },
      default: undefined,
    };

    const resolveAwsSdkSigV4Config = (config) => {
      let inputCredentials = config.credentials;
      let isUserSupplied = !!config.credentials;
      let resolvedCredentials = undefined;
      Object.defineProperty(config, "credentials", {
        set(credentials) {
          if (
            credentials &&
            credentials !== inputCredentials &&
            credentials !== resolvedCredentials
          ) {
            isUserSupplied = true;
          }
          inputCredentials = credentials;
          const memoizedProvider = normalizeCredentialProvider(config, {
            credentials: inputCredentials,
            credentialDefaultProvider: config.credentialDefaultProvider,
          });
          const boundProvider = bindCallerConfig(config, memoizedProvider);
          if (isUserSupplied && !boundProvider.attributed) {
            resolvedCredentials = async (options) =>
              boundProvider(options).then((creds) =>
                client.setCredentialFeature(creds, "CREDENTIALS_CODE", "e"),
              );
            resolvedCredentials.memoized = boundProvider.memoized;
            resolvedCredentials.configBound = boundProvider.configBound;
            resolvedCredentials.attributed = true;
          } else {
            resolvedCredentials = boundProvider;
          }
        },
        get() {
          return resolvedCredentials;
        },
        enumerable: true,
        configurable: true,
      });
      config.credentials = inputCredentials;
      const {
        signingEscapePath = true,
        systemClockOffset = config.systemClockOffset || 0,
        sha256,
      } = config;
      let signer;
      if (config.signer) {
        signer = core.normalizeProvider(config.signer);
      } else if (config.regionInfoProvider) {
        signer = () =>
          core
            .normalizeProvider(config.region)()
            .then(async (region) => [
              (await config.regionInfoProvider(region, {
                useFipsEndpoint: await config.useFipsEndpoint(),
                useDualstackEndpoint: await config.useDualstackEndpoint(),
              })) || {},
              region,
            ])
            .then(([regionInfo, region]) => {
              const { signingRegion, signingService } = regionInfo;
              config.signingRegion =
                config.signingRegion || signingRegion || region;
              config.signingName =
                config.signingName || signingService || config.serviceId;
              const params = {
                ...config,
                credentials: config.credentials,
                region: config.signingRegion,
                service: config.signingName,
                sha256,
                uriEscapePath: signingEscapePath,
              };
              const SignerCtor =
                config.signerConstructor || signatureV4.SignatureV4;
              return new SignerCtor(params);
            });
      } else {
        signer = async (authScheme) => {
          authScheme = Object.assign(
            {},
            {
              name: "sigv4",
              signingName: config.signingName || config.defaultSigningName,
              signingRegion: await core.normalizeProvider(config.region)(),
              properties: {},
            },
            authScheme,
          );
          const signingRegion = authScheme.signingRegion;
          const signingService = authScheme.signingName;
          config.signingRegion = config.signingRegion || signingRegion;
          config.signingName =
            config.signingName || signingService || config.serviceId;
          const params = {
            ...config,
            credentials: config.credentials,
            region: config.signingRegion,
            service: config.signingName,
            sha256,
            uriEscapePath: signingEscapePath,
          };
          const SignerCtor =
            config.signerConstructor || signatureV4.SignatureV4;
          return new SignerCtor(params);
        };
      }
      const resolvedConfig = Object.assign(config, {
        systemClockOffset,
        signingEscapePath,
        signer,
      });
      return resolvedConfig;
    };
    const resolveAWSSDKSigV4Config = resolveAwsSdkSigV4Config;
    function normalizeCredentialProvider(
      config,
      { credentials, credentialDefaultProvider },
    ) {
      let credentialsProvider;
      if (credentials) {
        if (!credentials?.memoized) {
          credentialsProvider = core.memoizeIdentityProvider(
            credentials,
            core.isIdentityExpired,
            core.doesIdentityRequireRefresh,
          );
        } else {
          credentialsProvider = credentials;
        }
      } else {
        if (credentialDefaultProvider) {
          credentialsProvider = core.normalizeProvider(
            credentialDefaultProvider(
              Object.assign({}, config, {
                parentClientConfig: config,
              }),
            ),
          );
        } else {
          credentialsProvider = async () => {
            throw new Error(
              "@aws-sdk/core::resolveAwsSdkSigV4Config - `credentials` not provided and no credentialDefaultProvider was configured.",
            );
          };
        }
      }
      credentialsProvider.memoized = true;
      return credentialsProvider;
    }
    function bindCallerConfig(config, credentialsProvider) {
      if (credentialsProvider.configBound) {
        return credentialsProvider;
      }
      const fn = async (options) =>
        credentialsProvider({ ...options, callerClientConfig: config });
      fn.memoized = credentialsProvider.memoized;
      fn.configBound = true;
      return fn;
    }

    class ProtocolLib {
      queryCompat;
      constructor(queryCompat = false) {
        this.queryCompat = queryCompat;
      }
      resolveRestContentType(defaultContentType, inputSchema) {
        const members = inputSchema.getMemberSchemas();
        const httpPayloadMember = Object.values(members).find((m) => {
          return !!m.getMergedTraits().httpPayload;
        });
        if (httpPayloadMember) {
          const mediaType = httpPayloadMember.getMergedTraits().mediaType;
          if (mediaType) {
            return mediaType;
          } else if (httpPayloadMember.isStringSchema()) {
            return "text/plain";
          } else if (httpPayloadMember.isBlobSchema()) {
            return "application/octet-stream";
          } else {
            return defaultContentType;
          }
        } else if (!inputSchema.isUnitSchema()) {
          const hasBody = Object.values(members).find((m) => {
            const {
              httpQuery,
              httpQueryParams,
              httpHeader,
              httpLabel,
              httpPrefixHeaders,
            } = m.getMergedTraits();
            const noPrefixHeaders = httpPrefixHeaders === void 0;
            return (
              !httpQuery &&
              !httpQueryParams &&
              !httpHeader &&
              !httpLabel &&
              noPrefixHeaders
            );
          });
          if (hasBody) {
            return defaultContentType;
          }
        }
      }
      async getErrorSchemaOrThrowBaseException(
        errorIdentifier,
        defaultNamespace,
        response,
        dataObject,
        metadata,
        getErrorSchema,
      ) {
        let namespace = defaultNamespace;
        let errorName = errorIdentifier;
        if (errorIdentifier.includes("#")) {
          [namespace, errorName] = errorIdentifier.split("#");
        }
        const errorMetadata = {
          $metadata: metadata,
          $fault: response.statusCode < 500 ? "client" : "server",
        };
        const registry = schema.TypeRegistry.for(namespace);
        try {
          const errorSchema =
            getErrorSchema?.(registry, errorName) ??
            registry.getSchema(errorIdentifier);
          return { errorSchema, errorMetadata };
        } catch (e) {
          dataObject.message =
            dataObject.message ?? dataObject.Message ?? "UnknownError";
          const synthetic = schema.TypeRegistry.for(
            "smithy.ts.sdk.synthetic." + namespace,
          );
          const baseExceptionSchema = synthetic.getBaseException();
          if (baseExceptionSchema) {
            const ErrorCtor =
              synthetic.getErrorCtor(baseExceptionSchema) ?? Error;
            throw this.decorateServiceException(
              Object.assign(new ErrorCtor({ name: errorName }), errorMetadata),
              dataObject,
            );
          }
          throw this.decorateServiceException(
            Object.assign(new Error(errorName), errorMetadata),
            dataObject,
          );
        }
      }
      decorateServiceException(exception, additions = {}) {
        if (this.queryCompat) {
          const msg = exception.Message ?? additions.Message;
          const error = smithyClient.decorateServiceException(
            exception,
            additions,
          );
          if (msg) {
            error.Message = msg;
            error.message = msg;
          }
          return error;
        }
        return smithyClient.decorateServiceException(exception, additions);
      }
      setQueryCompatError(output, response) {
        const queryErrorHeader = response.headers?.["x-amzn-query-error"];
        if (output !== undefined && queryErrorHeader != null) {
          const [Code, Type] = queryErrorHeader.split(";");
          const entries = Object.entries(output);
          const Error = {
            Code,
            Type,
          };
          Object.assign(output, Error);
          for (const [k, v] of entries) {
            Error[k] = v;
          }
          delete Error.__type;
          output.Error = Error;
        }
      }
      queryCompatOutput(queryCompatErrorData, errorData) {
        if (queryCompatErrorData.Error) {
          errorData.Error = queryCompatErrorData.Error;
        }
        if (queryCompatErrorData.Type) {
          errorData.Type = queryCompatErrorData.Type;
        }
        if (queryCompatErrorData.Code) {
          errorData.Code = queryCompatErrorData.Code;
        }
      }
    }

    class AwsSmithyRpcV2CborProtocol extends cbor.SmithyRpcV2CborProtocol {
      awsQueryCompatible;
      mixin;
      constructor({ defaultNamespace, awsQueryCompatible }) {
        super({ defaultNamespace });
        this.awsQueryCompatible = !!awsQueryCompatible;
        this.mixin = new ProtocolLib(this.awsQueryCompatible);
      }
      async serializeRequest(operationSchema, input, context) {
        const request = await super.serializeRequest(
          operationSchema,
          input,
          context,
        );
        if (this.awsQueryCompatible) {
          request.headers["x-amzn-query-mode"] = "true";
        }
        return request;
      }
      async handleError(
        operationSchema,
        context,
        response,
        dataObject,
        metadata,
      ) {
        if (this.awsQueryCompatible) {
          this.mixin.setQueryCompatError(dataObject, response);
        }
        const errorName =
          cbor.loadSmithyRpcV2CborErrorCode(response, dataObject) ?? "Unknown";
        const { errorSchema, errorMetadata } =
          await this.mixin.getErrorSchemaOrThrowBaseException(
            errorName,
            this.options.defaultNamespace,
            response,
            dataObject,
            metadata,
          );
        const ns = schema.NormalizedSchema.of(errorSchema);
        const message = dataObject.message ?? dataObject.Message ?? "Unknown";
        const ErrorCtor =
          schema.TypeRegistry.for(errorSchema[1]).getErrorCtor(errorSchema) ??
          Error;
        const exception = new ErrorCtor(message);
        const output = {};
        for (const [name, member] of ns.structIterator()) {
          output[name] = this.deserializer.readValue(member, dataObject[name]);
        }
        if (this.awsQueryCompatible) {
          this.mixin.queryCompatOutput(dataObject, output);
        }
        throw this.mixin.decorateServiceException(
          Object.assign(
            exception,
            errorMetadata,
            {
              $fault: ns.getMergedTraits().error,
              message,
            },
            output,
          ),
          dataObject,
        );
      }
    }

    const _toStr = (val) => {
      if (val == null) {
        return val;
      }
      if (typeof val === "number" || typeof val === "bigint") {
        const warning = new Error(
          `Received number ${val} where a string was expected.`,
        );
        warning.name = "Warning";
        console.warn(warning);
        return String(val);
      }
      if (typeof val === "boolean") {
        const warning = new Error(
          `Received boolean ${val} where a string was expected.`,
        );
        warning.name = "Warning";
        console.warn(warning);
        return String(val);
      }
      return val;
    };
    const _toBool = (val) => {
      if (val == null) {
        return val;
      }
      if (typeof val === "string") {
        const lowercase = val.toLowerCase();
        if (val !== "" && lowercase !== "false" && lowercase !== "true") {
          const warning = new Error(
            `Received string "${val}" where a boolean was expected.`,
          );
          warning.name = "Warning";
          console.warn(warning);
        }
        return val !== "" && lowercase !== "false";
      }
      return val;
    };
    const _toNum = (val) => {
      if (val == null) {
        return val;
      }
      if (typeof val === "string") {
        const num = Number(val);
        if (num.toString() !== val) {
          const warning = new Error(
            `Received string "${val}" where a number was expected.`,
          );
          warning.name = "Warning";
          console.warn(warning);
          return val;
        }
        return num;
      }
      return val;
    };

    class SerdeContextConfig {
      serdeContext;
      setSerdeContext(serdeContext) {
        this.serdeContext = serdeContext;
      }
    }

    function jsonReviver(key, value, context) {
      if (context?.source) {
        const numericString = context.source;
        if (typeof value === "number") {
          if (
            value > Number.MAX_SAFE_INTEGER ||
            value < Number.MIN_SAFE_INTEGER ||
            numericString !== String(value)
          ) {
            const isFractional = numericString.includes(".");
            if (isFractional) {
              return new serde.NumericValue(numericString, "bigDecimal");
            } else {
              return BigInt(numericString);
            }
          }
        }
      }
      return value;
    }

    const collectBodyString = (streamBody, context) =>
      smithyClient
        .collectBody(streamBody, context)
        .then((body) => (context?.utf8Encoder ?? utilUtf8.toUtf8)(body));

    const parseJsonBody = (streamBody, context) =>
      collectBodyString(streamBody, context).then((encoded) => {
        if (encoded.length) {
          try {
            return JSON.parse(encoded);
          } catch (e) {
            if (e?.name === "SyntaxError") {
              Object.defineProperty(e, "$responseBodyText", {
                value: encoded,
              });
            }
            throw e;
          }
        }
        return {};
      });
    const parseJsonErrorBody = async (errorBody, context) => {
      const value = await parseJsonBody(errorBody, context);
      value.message = value.message ?? value.Message;
      return value;
    };
    const loadRestJsonErrorCode = (output, data) => {
      const findKey = (object, key) =>
        Object.keys(object).find((k) => k.toLowerCase() === key.toLowerCase());
      const sanitizeErrorCode = (rawValue) => {
        let cleanValue = rawValue;
        if (typeof cleanValue === "number") {
          cleanValue = cleanValue.toString();
        }
        if (cleanValue.indexOf(",") >= 0) {
          cleanValue = cleanValue.split(",")[0];
        }
        if (cleanValue.indexOf(":") >= 0) {
          cleanValue = cleanValue.split(":")[0];
        }
        if (cleanValue.indexOf("#") >= 0) {
          cleanValue = cleanValue.split("#")[1];
        }
        return cleanValue;
      };
      const headerKey = findKey(output.headers, "x-amzn-errortype");
      if (headerKey !== undefined) {
        return sanitizeErrorCode(output.headers[headerKey]);
      }
      if (data && typeof data === "object") {
        const codeKey = findKey(data, "code");
        if (codeKey && data[codeKey] !== undefined) {
          return sanitizeErrorCode(data[codeKey]);
        }
        if (data["__type"] !== undefined) {
          return sanitizeErrorCode(data["__type"]);
        }
      }
    };

    class JsonShapeDeserializer extends SerdeContextConfig {
      settings;
      constructor(settings) {
        super();
        this.settings = settings;
      }
      async read(schema, data) {
        return this._read(
          schema,
          typeof data === "string"
            ? JSON.parse(data, jsonReviver)
            : await parseJsonBody(data, this.serdeContext),
        );
      }
      readObject(schema, data) {
        return this._read(schema, data);
      }
      _read(schema$1, value) {
        const isObject = value !== null && typeof value === "object";
        const ns = schema.NormalizedSchema.of(schema$1);
        if (ns.isListSchema() && Array.isArray(value)) {
          const listMember = ns.getValueSchema();
          const out = [];
          const sparse = !!ns.getMergedTraits().sparse;
          for (const item of value) {
            if (sparse || item != null) {
              out.push(this._read(listMember, item));
            }
          }
          return out;
        } else if (ns.isMapSchema() && isObject) {
          const mapMember = ns.getValueSchema();
          const out = {};
          const sparse = !!ns.getMergedTraits().sparse;
          for (const [_k, _v] of Object.entries(value)) {
            if (sparse || _v != null) {
              out[_k] = this._read(mapMember, _v);
            }
          }
          return out;
        } else if (ns.isStructSchema() && isObject) {
          const out = {};
          for (const [memberName, memberSchema] of ns.structIterator()) {
            const fromKey = this.settings.jsonName
              ? (memberSchema.getMergedTraits().jsonName ?? memberName)
              : memberName;
            const deserializedValue = this._read(memberSchema, value[fromKey]);
            if (deserializedValue != null) {
              out[memberName] = deserializedValue;
            }
          }
          return out;
        }
        if (ns.isBlobSchema() && typeof value === "string") {
          return utilBase64.fromBase64(value);
        }
        const mediaType = ns.getMergedTraits().mediaType;
        if (ns.isStringSchema() && typeof value === "string" && mediaType) {
          const isJson =
            mediaType === "application/json" || mediaType.endsWith("+json");
          if (isJson) {
            return serde.LazyJsonString.from(value);
          }
        }
        if (ns.isTimestampSchema() && value != null) {
          const format = protocols.determineTimestampFormat(ns, this.settings);
          switch (format) {
            case 5:
              return serde.parseRfc3339DateTimeWithOffset(value);
            case 6:
              return serde.parseRfc7231DateTime(value);
            case 7:
              return serde.parseEpochTimestamp(value);
            default:
              console.warn(
                "Missing timestamp format, parsing value with Date constructor:",
                value,
              );
              return new Date(value);
          }
        }
        if (
          ns.isBigIntegerSchema() &&
          (typeof value === "number" || typeof value === "string")
        ) {
          return BigInt(value);
        }
        if (ns.isBigDecimalSchema() && value != undefined) {
          if (value instanceof serde.NumericValue) {
            return value;
          }
          const untyped = value;
          if (untyped.type === "bigDecimal" && "string" in untyped) {
            return new serde.NumericValue(untyped.string, untyped.type);
          }
          return new serde.NumericValue(String(value), "bigDecimal");
        }
        if (ns.isNumericSchema() && typeof value === "string") {
          switch (value) {
            case "Infinity":
              return Infinity;
            case "-Infinity":
              return -Infinity;
            case "NaN":
              return NaN;
          }
        }
        if (ns.isDocumentSchema()) {
          if (isObject) {
            const out = Array.isArray(value) ? [] : {};
            for (const [k, v] of Object.entries(value)) {
              if (v instanceof serde.NumericValue) {
                out[k] = v;
              } else {
                out[k] = this._read(ns, v);
              }
            }
            return out;
          } else {
            return structuredClone(value);
          }
        }
        return value;
      }
    }

    const NUMERIC_CONTROL_CHAR = String.fromCharCode(925);
    class JsonReplacer {
      values = new Map();
      counter = 0;
      stage = 0;
      createReplacer() {
        if (this.stage === 1) {
          throw new Error(
            "@aws-sdk/core/protocols - JsonReplacer already created.",
          );
        }
        if (this.stage === 2) {
          throw new Error("@aws-sdk/core/protocols - JsonReplacer exhausted.");
        }
        this.stage = 1;
        return (key, value) => {
          if (value instanceof serde.NumericValue) {
            const v =
              `${NUMERIC_CONTROL_CHAR + "nv" + this.counter++}_` + value.string;
            this.values.set(`"${v}"`, value.string);
            return v;
          }
          if (typeof value === "bigint") {
            const s = value.toString();
            const v = `${NUMERIC_CONTROL_CHAR + "b" + this.counter++}_` + s;
            this.values.set(`"${v}"`, s);
            return v;
          }
          return value;
        };
      }
      replaceInJson(json) {
        if (this.stage === 0) {
          throw new Error(
            "@aws-sdk/core/protocols - JsonReplacer not created yet.",
          );
        }
        if (this.stage === 2) {
          throw new Error("@aws-sdk/core/protocols - JsonReplacer exhausted.");
        }
        this.stage = 2;
        if (this.counter === 0) {
          return json;
        }
        for (const [key, value] of this.values) {
          json = json.replace(key, value);
        }
        return json;
      }
    }

    class JsonShapeSerializer extends SerdeContextConfig {
      settings;
      buffer;
      rootSchema;
      constructor(settings) {
        super();
        this.settings = settings;
      }
      write(schema$1, value) {
        this.rootSchema = schema.NormalizedSchema.of(schema$1);
        this.buffer = this._write(this.rootSchema, value);
      }
      writeDiscriminatedDocument(schema$1, value) {
        this.write(schema$1, value);
        if (typeof this.buffer === "object") {
          this.buffer.__type =
            schema.NormalizedSchema.of(schema$1).getName(true);
        }
      }
      flush() {
        const { rootSchema } = this;
        this.rootSchema = undefined;
        if (rootSchema?.isStructSchema() || rootSchema?.isDocumentSchema()) {
          const replacer = new JsonReplacer();
          return replacer.replaceInJson(
            JSON.stringify(this.buffer, replacer.createReplacer(), 0),
          );
        }
        return this.buffer;
      }
      _write(schema$1, value, container) {
        const isObject = value !== null && typeof value === "object";
        const ns = schema.NormalizedSchema.of(schema$1);
        if (ns.isListSchema() && Array.isArray(value)) {
          const listMember = ns.getValueSchema();
          const out = [];
          const sparse = !!ns.getMergedTraits().sparse;
          for (const item of value) {
            if (sparse || item != null) {
              out.push(this._write(listMember, item));
            }
          }
          return out;
        } else if (ns.isMapSchema() && isObject) {
          const mapMember = ns.getValueSchema();
          const out = {};
          const sparse = !!ns.getMergedTraits().sparse;
          for (const [_k, _v] of Object.entries(value)) {
            if (sparse || _v != null) {
              out[_k] = this._write(mapMember, _v);
            }
          }
          return out;
        } else if (ns.isStructSchema() && isObject) {
          const out = {};
          for (const [memberName, memberSchema] of ns.structIterator()) {
            const targetKey = this.settings.jsonName
              ? (memberSchema.getMergedTraits().jsonName ?? memberName)
              : memberName;
            const serializableValue = this._write(
              memberSchema,
              value[memberName],
              ns,
            );
            if (serializableValue !== undefined) {
              out[targetKey] = serializableValue;
            }
          }
          return out;
        }
        if (value === null && container?.isStructSchema()) {
          return void 0;
        }
        if (
          (ns.isBlobSchema() &&
            (value instanceof Uint8Array || typeof value === "string")) ||
          (ns.isDocumentSchema() && value instanceof Uint8Array)
        ) {
          if (ns === this.rootSchema) {
            return value;
          }
          return (this.serdeContext?.base64Encoder ?? utilBase64.toBase64)(
            value,
          );
        }
        if (
          (ns.isTimestampSchema() || ns.isDocumentSchema()) &&
          value instanceof Date
        ) {
          const format = protocols.determineTimestampFormat(ns, this.settings);
          switch (format) {
            case 5:
              return value.toISOString().replace(".000Z", "Z");
            case 6:
              return serde.dateToUtcString(value);
            case 7:
              return value.getTime() / 1000;
            default:
              console.warn(
                "Missing timestamp format, using epoch seconds",
                value,
              );
              return value.getTime() / 1000;
          }
        }
        if (ns.isNumericSchema() && typeof value === "number") {
          if (Math.abs(value) === Infinity || isNaN(value)) {
            return String(value);
          }
        }
        if (ns.isStringSchema()) {
          if (typeof value === "undefined" && ns.isIdempotencyToken()) {
            return serde.generateIdempotencyToken();
          }
          const mediaType = ns.getMergedTraits().mediaType;
          if (value != null && mediaType) {
            const isJson =
              mediaType === "application/json" || mediaType.endsWith("+json");
            if (isJson) {
              return serde.LazyJsonString.from(value);
            }
          }
        }
        if (ns.isDocumentSchema()) {
          if (isObject) {
            const out = Array.isArray(value) ? [] : {};
            for (const [k, v] of Object.entries(value)) {
              if (v instanceof serde.NumericValue) {
                out[k] = v;
              } else {
                out[k] = this._write(ns, v);
              }
            }
            return out;
          } else {
            return structuredClone(value);
          }
        }
        return value;
      }
    }

    class JsonCodec extends SerdeContextConfig {
      settings;
      constructor(settings) {
        super();
        this.settings = settings;
      }
      createSerializer() {
        const serializer = new JsonShapeSerializer(this.settings);
        serializer.setSerdeContext(this.serdeContext);
        return serializer;
      }
      createDeserializer() {
        const deserializer = new JsonShapeDeserializer(this.settings);
        deserializer.setSerdeContext(this.serdeContext);
        return deserializer;
      }
    }

    class AwsJsonRpcProtocol extends protocols.RpcProtocol {
      serializer;
      deserializer;
      serviceTarget;
      codec;
      mixin;
      awsQueryCompatible;
      constructor({ defaultNamespace, serviceTarget, awsQueryCompatible }) {
        super({
          defaultNamespace,
        });
        this.serviceTarget = serviceTarget;
        this.codec = new JsonCodec({
          timestampFormat: {
            useTrait: true,
            default: 7,
          },
          jsonName: false,
        });
        this.serializer = this.codec.createSerializer();
        this.deserializer = this.codec.createDeserializer();
        this.awsQueryCompatible = !!awsQueryCompatible;
        this.mixin = new ProtocolLib(this.awsQueryCompatible);
      }
      async serializeRequest(operationSchema, input, context) {
        const request = await super.serializeRequest(
          operationSchema,
          input,
          context,
        );
        if (!request.path.endsWith("/")) {
          request.path += "/";
        }
        Object.assign(request.headers, {
          "content-type": `application/x-amz-json-${this.getJsonRpcVersion()}`,
          "x-amz-target": `${this.serviceTarget}.${operationSchema.name}`,
        });
        if (this.awsQueryCompatible) {
          request.headers["x-amzn-query-mode"] = "true";
        }
        if (schema.deref(operationSchema.input) === "unit" || !request.body) {
          request.body = "{}";
        }
        return request;
      }
      getPayloadCodec() {
        return this.codec;
      }
      async handleError(
        operationSchema,
        context,
        response,
        dataObject,
        metadata,
      ) {
        if (this.awsQueryCompatible) {
          this.mixin.setQueryCompatError(dataObject, response);
        }
        const errorIdentifier =
          loadRestJsonErrorCode(response, dataObject) ?? "Unknown";
        const { errorSchema, errorMetadata } =
          await this.mixin.getErrorSchemaOrThrowBaseException(
            errorIdentifier,
            this.options.defaultNamespace,
            response,
            dataObject,
            metadata,
          );
        const ns = schema.NormalizedSchema.of(errorSchema);
        const message = dataObject.message ?? dataObject.Message ?? "Unknown";
        const ErrorCtor =
          schema.TypeRegistry.for(errorSchema[1]).getErrorCtor(errorSchema) ??
          Error;
        const exception = new ErrorCtor(message);
        const output = {};
        for (const [name, member] of ns.structIterator()) {
          const target = member.getMergedTraits().jsonName ?? name;
          output[name] = this.codec
            .createDeserializer()
            .readObject(member, dataObject[target]);
        }
        if (this.awsQueryCompatible) {
          this.mixin.queryCompatOutput(dataObject, output);
        }
        throw this.mixin.decorateServiceException(
          Object.assign(
            exception,
            errorMetadata,
            {
              $fault: ns.getMergedTraits().error,
              message,
            },
            output,
          ),
          dataObject,
        );
      }
    }

    class AwsJson1_0Protocol extends AwsJsonRpcProtocol {
      constructor({ defaultNamespace, serviceTarget, awsQueryCompatible }) {
        super({
          defaultNamespace,
          serviceTarget,
          awsQueryCompatible,
        });
      }
      getShapeId() {
        return "aws.protocols#awsJson1_0";
      }
      getJsonRpcVersion() {
        return "1.0";
      }
      getDefaultContentType() {
        return "application/x-amz-json-1.0";
      }
    }

    class AwsJson1_1Protocol extends AwsJsonRpcProtocol {
      constructor({ defaultNamespace, serviceTarget, awsQueryCompatible }) {
        super({
          defaultNamespace,
          serviceTarget,
          awsQueryCompatible,
        });
      }
      getShapeId() {
        return "aws.protocols#awsJson1_1";
      }
      getJsonRpcVersion() {
        return "1.1";
      }
      getDefaultContentType() {
        return "application/x-amz-json-1.1";
      }
    }

    class AwsRestJsonProtocol extends protocols.HttpBindingProtocol {
      serializer;
      deserializer;
      codec;
      mixin = new ProtocolLib();
      constructor({ defaultNamespace }) {
        super({
          defaultNamespace,
        });
        const settings = {
          timestampFormat: {
            useTrait: true,
            default: 7,
          },
          httpBindings: true,
          jsonName: true,
        };
        this.codec = new JsonCodec(settings);
        this.serializer = new protocols.HttpInterceptingShapeSerializer(
          this.codec.createSerializer(),
          settings,
        );
        this.deserializer = new protocols.HttpInterceptingShapeDeserializer(
          this.codec.createDeserializer(),
          settings,
        );
      }
      getShapeId() {
        return "aws.protocols#restJson1";
      }
      getPayloadCodec() {
        return this.codec;
      }
      setSerdeContext(serdeContext) {
        this.codec.setSerdeContext(serdeContext);
        super.setSerdeContext(serdeContext);
      }
      async serializeRequest(operationSchema, input, context) {
        const request = await super.serializeRequest(
          operationSchema,
          input,
          context,
        );
        const inputSchema = schema.NormalizedSchema.of(operationSchema.input);
        if (!request.headers["content-type"]) {
          const contentType = this.mixin.resolveRestContentType(
            this.getDefaultContentType(),
            inputSchema,
          );
          if (contentType) {
            request.headers["content-type"] = contentType;
          }
        }
        if (
          request.body == null &&
          request.headers["content-type"] === this.getDefaultContentType()
        ) {
          request.body = "{}";
        }
        return request;
      }
      async deserializeResponse(operationSchema, context, response) {
        const output = await super.deserializeResponse(
          operationSchema,
          context,
          response,
        );
        const outputSchema = schema.NormalizedSchema.of(operationSchema.output);
        for (const [name, member] of outputSchema.structIterator()) {
          if (member.getMemberTraits().httpPayload && !(name in output)) {
            output[name] = null;
          }
        }
        return output;
      }
      async handleError(
        operationSchema,
        context,
        response,
        dataObject,
        metadata,
      ) {
        const errorIdentifier =
          loadRestJsonErrorCode(response, dataObject) ?? "Unknown";
        const { errorSchema, errorMetadata } =
          await this.mixin.getErrorSchemaOrThrowBaseException(
            errorIdentifier,
            this.options.defaultNamespace,
            response,
            dataObject,
            metadata,
          );
        const ns = schema.NormalizedSchema.of(errorSchema);
        const message = dataObject.message ?? dataObject.Message ?? "Unknown";
        const ErrorCtor =
          schema.TypeRegistry.for(errorSchema[1]).getErrorCtor(errorSchema) ??
          Error;
        const exception = new ErrorCtor(message);
        await this.deserializeHttpMessage(
          errorSchema,
          context,
          response,
          dataObject,
        );
        const output = {};
        for (const [name, member] of ns.structIterator()) {
          const target = member.getMergedTraits().jsonName ?? name;
          output[name] = this.codec
            .createDeserializer()
            .readObject(member, dataObject[target]);
        }
        throw this.mixin.decorateServiceException(
          Object.assign(
            exception,
            errorMetadata,
            {
              $fault: ns.getMergedTraits().error,
              message,
            },
            output,
          ),
          dataObject,
        );
      }
      getDefaultContentType() {
        return "application/json";
      }
    }

    const awsExpectUnion = (value) => {
      if (value == null) {
        return undefined;
      }
      if (typeof value === "object" && "__type" in value) {
        delete value.__type;
      }
      return smithyClient.expectUnion(value);
    };

    class XmlShapeDeserializer extends SerdeContextConfig {
      settings;
      stringDeserializer;
      constructor(settings) {
        super();
        this.settings = settings;
        this.stringDeserializer = new protocols.FromStringShapeDeserializer(
          settings,
        );
      }
      setSerdeContext(serdeContext) {
        this.serdeContext = serdeContext;
        this.stringDeserializer.setSerdeContext(serdeContext);
      }
      read(schema$1, bytes, key) {
        const ns = schema.NormalizedSchema.of(schema$1);
        const memberSchemas = ns.getMemberSchemas();
        const isEventPayload =
          ns.isStructSchema() &&
          ns.isMemberSchema() &&
          !!Object.values(memberSchemas).find((memberNs) => {
            return !!memberNs.getMemberTraits().eventPayload;
          });
        if (isEventPayload) {
          const output = {};
          const memberName = Object.keys(memberSchemas)[0];
          const eventMemberSchema = memberSchemas[memberName];
          if (eventMemberSchema.isBlobSchema()) {
            output[memberName] = bytes;
          } else {
            output[memberName] = this.read(memberSchemas[memberName], bytes);
          }
          return output;
        }
        const xmlString = (this.serdeContext?.utf8Encoder ?? utilUtf8.toUtf8)(
          bytes,
        );
        const parsedObject = this.parseXml(xmlString);
        return this.readSchema(
          schema$1,
          key ? parsedObject[key] : parsedObject,
        );
      }
      readSchema(_schema, value) {
        const ns = schema.NormalizedSchema.of(_schema);
        if (ns.isUnitSchema()) {
          return;
        }
        const traits = ns.getMergedTraits();
        if (ns.isListSchema() && !Array.isArray(value)) {
          return this.readSchema(ns, [value]);
        }
        if (value == null) {
          return value;
        }
        if (typeof value === "object") {
          const sparse = !!traits.sparse;
          const flat = !!traits.xmlFlattened;
          if (ns.isListSchema()) {
            const listValue = ns.getValueSchema();
            const buffer = [];
            const sourceKey = listValue.getMergedTraits().xmlName ?? "member";
            const source = flat ? value : (value[0] ?? value)[sourceKey];
            const sourceArray = Array.isArray(source) ? source : [source];
            for (const v of sourceArray) {
              if (v != null || sparse) {
                buffer.push(this.readSchema(listValue, v));
              }
            }
            return buffer;
          }
          const buffer = {};
          if (ns.isMapSchema()) {
            const keyNs = ns.getKeySchema();
            const memberNs = ns.getValueSchema();
            let entries;
            if (flat) {
              entries = Array.isArray(value) ? value : [value];
            } else {
              entries = Array.isArray(value.entry)
                ? value.entry
                : [value.entry];
            }
            const keyProperty = keyNs.getMergedTraits().xmlName ?? "key";
            const valueProperty = memberNs.getMergedTraits().xmlName ?? "value";
            for (const entry of entries) {
              const key = entry[keyProperty];
              const value = entry[valueProperty];
              if (value != null || sparse) {
                buffer[key] = this.readSchema(memberNs, value);
              }
            }
            return buffer;
          }
          if (ns.isStructSchema()) {
            for (const [memberName, memberSchema] of ns.structIterator()) {
              const memberTraits = memberSchema.getMergedTraits();
              const xmlObjectKey = !memberTraits.httpPayload
                ? (memberSchema.getMemberTraits().xmlName ?? memberName)
                : (memberTraits.xmlName ?? memberSchema.getName());
              if (value[xmlObjectKey] != null) {
                buffer[memberName] = this.readSchema(
                  memberSchema,
                  value[xmlObjectKey],
                );
              }
            }
            return buffer;
          }
          if (ns.isDocumentSchema()) {
            return value;
          }
          throw new Error(
            `@aws-sdk/core/protocols - xml deserializer unhandled schema type for ${ns.getName(true)}`,
          );
        }
        if (ns.isListSchema()) {
          return [];
        }
        if (ns.isMapSchema() || ns.isStructSchema()) {
          return {};
        }
        return this.stringDeserializer.read(ns, value);
      }
      parseXml(xml) {
        if (xml.length) {
          let parsedObj;
          try {
            parsedObj = xmlBuilder.parseXML(xml);
          } catch (e) {
            if (e && typeof e === "object") {
              Object.defineProperty(e, "$responseBodyText", {
                value: xml,
              });
            }
            throw e;
          }
          const textNodeName = "#text";
          const key = Object.keys(parsedObj)[0];
          const parsedObjToReturn = parsedObj[key];
          if (parsedObjToReturn[textNodeName]) {
            parsedObjToReturn[key] = parsedObjToReturn[textNodeName];
            delete parsedObjToReturn[textNodeName];
          }
          return smithyClient.getValueFromTextNode(parsedObjToReturn);
        }
        return {};
      }
    }

    class QueryShapeSerializer extends SerdeContextConfig {
      settings;
      buffer;
      constructor(settings) {
        super();
        this.settings = settings;
      }
      write(schema$1, value, prefix = "") {
        if (this.buffer === undefined) {
          this.buffer = "";
        }
        const ns = schema.NormalizedSchema.of(schema$1);
        if (prefix && !prefix.endsWith(".")) {
          prefix += ".";
        }
        if (ns.isBlobSchema()) {
          if (typeof value === "string" || value instanceof Uint8Array) {
            this.writeKey(prefix);
            this.writeValue(
              (this.serdeContext?.base64Encoder ?? utilBase64.toBase64)(value),
            );
          }
        } else if (
          ns.isBooleanSchema() ||
          ns.isNumericSchema() ||
          ns.isStringSchema()
        ) {
          if (value != null) {
            this.writeKey(prefix);
            this.writeValue(String(value));
          } else if (ns.isIdempotencyToken()) {
            this.writeKey(prefix);
            this.writeValue(serde.generateIdempotencyToken());
          }
        } else if (ns.isBigIntegerSchema()) {
          if (value != null) {
            this.writeKey(prefix);
            this.writeValue(String(value));
          }
        } else if (ns.isBigDecimalSchema()) {
          if (value != null) {
            this.writeKey(prefix);
            this.writeValue(
              value instanceof serde.NumericValue
                ? value.string
                : String(value),
            );
          }
        } else if (ns.isTimestampSchema()) {
          if (value instanceof Date) {
            this.writeKey(prefix);
            const format = protocols.determineTimestampFormat(
              ns,
              this.settings,
            );
            switch (format) {
              case 5:
                this.writeValue(value.toISOString().replace(".000Z", "Z"));
                break;
              case 6:
                this.writeValue(smithyClient.dateToUtcString(value));
                break;
              case 7:
                this.writeValue(String(value.getTime() / 1000));
                break;
            }
          }
        } else if (ns.isDocumentSchema()) {
          throw new Error(
            `@aws-sdk/core/protocols - QuerySerializer unsupported document type ${ns.getName(true)}`,
          );
        } else if (ns.isListSchema()) {
          if (Array.isArray(value)) {
            if (value.length === 0) {
              if (this.settings.serializeEmptyLists) {
                this.writeKey(prefix);
                this.writeValue("");
              }
            } else {
              const member = ns.getValueSchema();
              const flat =
                this.settings.flattenLists || ns.getMergedTraits().xmlFlattened;
              let i = 1;
              for (const item of value) {
                if (item == null) {
                  continue;
                }
                const suffix = this.getKey(
                  "member",
                  member.getMergedTraits().xmlName,
                );
                const key = flat ? `${prefix}${i}` : `${prefix}${suffix}.${i}`;
                this.write(member, item, key);
                ++i;
              }
            }
          }
        } else if (ns.isMapSchema()) {
          if (value && typeof value === "object") {
            const keySchema = ns.getKeySchema();
            const memberSchema = ns.getValueSchema();
            const flat = ns.getMergedTraits().xmlFlattened;
            let i = 1;
            for (const [k, v] of Object.entries(value)) {
              if (v == null) {
                continue;
              }
              const keySuffix = this.getKey(
                "key",
                keySchema.getMergedTraits().xmlName,
              );
              const key = flat
                ? `${prefix}${i}.${keySuffix}`
                : `${prefix}entry.${i}.${keySuffix}`;
              const valueSuffix = this.getKey(
                "value",
                memberSchema.getMergedTraits().xmlName,
              );
              const valueKey = flat
                ? `${prefix}${i}.${valueSuffix}`
                : `${prefix}entry.${i}.${valueSuffix}`;
              this.write(keySchema, k, key);
              this.write(memberSchema, v, valueKey);
              ++i;
            }
          }
        } else if (ns.isStructSchema()) {
          if (value && typeof value === "object") {
            for (const [memberName, member] of ns.structIterator()) {
              if (value[memberName] == null && !member.isIdempotencyToken()) {
                continue;
              }
              const suffix = this.getKey(
                memberName,
                member.getMergedTraits().xmlName,
              );
              const key = `${prefix}${suffix}`;
              this.write(member, value[memberName], key);
            }
          }
        } else if (ns.isUnitSchema());
        else {
          throw new Error(
            `@aws-sdk/core/protocols - QuerySerializer unrecognized schema type ${ns.getName(true)}`,
          );
        }
      }
      flush() {
        if (this.buffer === undefined) {
          throw new Error(
            "@aws-sdk/core/protocols - QuerySerializer cannot flush with nothing written to buffer.",
          );
        }
        const str = this.buffer;
        delete this.buffer;
        return str;
      }
      getKey(memberName, xmlName) {
        const key = xmlName ?? memberName;
        if (this.settings.capitalizeKeys) {
          return key[0].toUpperCase() + key.slice(1);
        }
        return key;
      }
      writeKey(key) {
        if (key.endsWith(".")) {
          key = key.slice(0, key.length - 1);
        }
        this.buffer += `&${protocols.extendedEncodeURIComponent(key)}=`;
      }
      writeValue(value) {
        this.buffer += protocols.extendedEncodeURIComponent(value);
      }
    }

    class AwsQueryProtocol extends protocols.RpcProtocol {
      options;
      serializer;
      deserializer;
      mixin = new ProtocolLib();
      constructor(options) {
        super({
          defaultNamespace: options.defaultNamespace,
        });
        this.options = options;
        const settings = {
          timestampFormat: {
            useTrait: true,
            default: 5,
          },
          httpBindings: false,
          xmlNamespace: options.xmlNamespace,
          serviceNamespace: options.defaultNamespace,
          serializeEmptyLists: true,
        };
        this.serializer = new QueryShapeSerializer(settings);
        this.deserializer = new XmlShapeDeserializer(settings);
      }
      getShapeId() {
        return "aws.protocols#awsQuery";
      }
      setSerdeContext(serdeContext) {
        this.serializer.setSerdeContext(serdeContext);
        this.deserializer.setSerdeContext(serdeContext);
      }
      getPayloadCodec() {
        throw new Error("AWSQuery protocol has no payload codec.");
      }
      async serializeRequest(operationSchema, input, context) {
        const request = await super.serializeRequest(
          operationSchema,
          input,
          context,
        );
        if (!request.path.endsWith("/")) {
          request.path += "/";
        }
        Object.assign(request.headers, {
          "content-type": `application/x-www-form-urlencoded`,
        });
        if (schema.deref(operationSchema.input) === "unit" || !request.body) {
          request.body = "";
        }
        const action =
          operationSchema.name.split("#")[1] ?? operationSchema.name;
        request.body =
          `Action=${action}&Version=${this.options.version}` + request.body;
        if (request.body.endsWith("&")) {
          request.body = request.body.slice(-1);
        }
        return request;
      }
      async deserializeResponse(operationSchema, context, response) {
        const deserializer = this.deserializer;
        const ns = schema.NormalizedSchema.of(operationSchema.output);
        const dataObject = {};
        if (response.statusCode >= 300) {
          const bytes = await protocols.collectBody(response.body, context);
          if (bytes.byteLength > 0) {
            Object.assign(dataObject, await deserializer.read(15, bytes));
          }
          await this.handleError(
            operationSchema,
            context,
            response,
            dataObject,
            this.deserializeMetadata(response),
          );
        }
        for (const header in response.headers) {
          const value = response.headers[header];
          delete response.headers[header];
          response.headers[header.toLowerCase()] = value;
        }
        const shortName =
          operationSchema.name.split("#")[1] ?? operationSchema.name;
        const awsQueryResultKey =
          ns.isStructSchema() && this.useNestedResult()
            ? shortName + "Result"
            : undefined;
        const bytes = await protocols.collectBody(response.body, context);
        if (bytes.byteLength > 0) {
          Object.assign(
            dataObject,
            await deserializer.read(ns, bytes, awsQueryResultKey),
          );
        }
        const output = {
          $metadata: this.deserializeMetadata(response),
          ...dataObject,
        };
        return output;
      }
      useNestedResult() {
        return true;
      }
      async handleError(
        operationSchema,
        context,
        response,
        dataObject,
        metadata,
      ) {
        const errorIdentifier =
          this.loadQueryErrorCode(response, dataObject) ?? "Unknown";
        const errorData = this.loadQueryError(dataObject);
        const message = this.loadQueryErrorMessage(dataObject);
        errorData.message = message;
        errorData.Error = {
          Type: errorData.Type,
          Code: errorData.Code,
          Message: message,
        };
        const { errorSchema, errorMetadata } =
          await this.mixin.getErrorSchemaOrThrowBaseException(
            errorIdentifier,
            this.options.defaultNamespace,
            response,
            errorData,
            metadata,
            (registry, errorName) => {
              try {
                return registry.getSchema(errorName);
              } catch (e) {
                return registry.find(
                  (schema$1) =>
                    schema.NormalizedSchema.of(schema$1).getMergedTraits()
                      .awsQueryError?.[0] === errorName,
                );
              }
            },
          );
        const ns = schema.NormalizedSchema.of(errorSchema);
        const ErrorCtor =
          schema.TypeRegistry.for(errorSchema[1]).getErrorCtor(errorSchema) ??
          Error;
        const exception = new ErrorCtor(message);
        const output = {
          Error: errorData.Error,
        };
        for (const [name, member] of ns.structIterator()) {
          const target = member.getMergedTraits().xmlName ?? name;
          const value = errorData[target] ?? dataObject[target];
          output[name] = this.deserializer.readSchema(member, value);
        }
        throw this.mixin.decorateServiceException(
          Object.assign(
            exception,
            errorMetadata,
            {
              $fault: ns.getMergedTraits().error,
              message,
            },
            output,
          ),
          dataObject,
        );
      }
      loadQueryErrorCode(output, data) {
        const code = (
          data.Errors?.[0]?.Error ??
          data.Errors?.Error ??
          data.Error
        )?.Code;
        if (code !== undefined) {
          return code;
        }
        if (output.statusCode == 404) {
          return "NotFound";
        }
      }
      loadQueryError(data) {
        return data.Errors?.[0]?.Error ?? data.Errors?.Error ?? data.Error;
      }
      loadQueryErrorMessage(data) {
        const errorData = this.loadQueryError(data);
        return (
          errorData?.message ??
          errorData?.Message ??
          data.message ??
          data.Message ??
          "Unknown"
        );
      }
      getDefaultContentType() {
        return "application/x-www-form-urlencoded";
      }
    }

    class AwsEc2QueryProtocol extends AwsQueryProtocol {
      options;
      constructor(options) {
        super(options);
        this.options = options;
        const ec2Settings = {
          capitalizeKeys: true,
          flattenLists: true,
          serializeEmptyLists: false,
        };
        Object.assign(this.serializer.settings, ec2Settings);
      }
      useNestedResult() {
        return false;
      }
    }

    const parseXmlBody = (streamBody, context) =>
      collectBodyString(streamBody, context).then((encoded) => {
        if (encoded.length) {
          let parsedObj;
          try {
            parsedObj = xmlBuilder.parseXML(encoded);
          } catch (e) {
            if (e && typeof e === "object") {
              Object.defineProperty(e, "$responseBodyText", {
                value: encoded,
              });
            }
            throw e;
          }
          const textNodeName = "#text";
          const key = Object.keys(parsedObj)[0];
          const parsedObjToReturn = parsedObj[key];
          if (parsedObjToReturn[textNodeName]) {
            parsedObjToReturn[key] = parsedObjToReturn[textNodeName];
            delete parsedObjToReturn[textNodeName];
          }
          return smithyClient.getValueFromTextNode(parsedObjToReturn);
        }
        return {};
      });
    const parseXmlErrorBody = async (errorBody, context) => {
      const value = await parseXmlBody(errorBody, context);
      if (value.Error) {
        value.Error.message = value.Error.message ?? value.Error.Message;
      }
      return value;
    };
    const loadRestXmlErrorCode = (output, data) => {
      if (data?.Error?.Code !== undefined) {
        return data.Error.Code;
      }
      if (data?.Code !== undefined) {
        return data.Code;
      }
      if (output.statusCode == 404) {
        return "NotFound";
      }
    };

    class XmlShapeSerializer extends SerdeContextConfig {
      settings;
      stringBuffer;
      byteBuffer;
      buffer;
      constructor(settings) {
        super();
        this.settings = settings;
      }
      write(schema$1, value) {
        const ns = schema.NormalizedSchema.of(schema$1);
        if (ns.isStringSchema() && typeof value === "string") {
          this.stringBuffer = value;
        } else if (ns.isBlobSchema()) {
          this.byteBuffer =
            "byteLength" in value
              ? value
              : (this.serdeContext?.base64Decoder ?? utilBase64.fromBase64)(
                  value,
                );
        } else {
          this.buffer = this.writeStruct(ns, value, undefined);
          const traits = ns.getMergedTraits();
          if (traits.httpPayload && !traits.xmlName) {
            this.buffer.withName(ns.getName());
          }
        }
      }
      flush() {
        if (this.byteBuffer !== undefined) {
          const bytes = this.byteBuffer;
          delete this.byteBuffer;
          return bytes;
        }
        if (this.stringBuffer !== undefined) {
          const str = this.stringBuffer;
          delete this.stringBuffer;
          return str;
        }
        const buffer = this.buffer;
        if (this.settings.xmlNamespace) {
          if (!buffer?.attributes?.["xmlns"]) {
            buffer.addAttribute("xmlns", this.settings.xmlNamespace);
          }
        }
        delete this.buffer;
        return buffer.toString();
      }
      writeStruct(ns, value, parentXmlns) {
        const traits = ns.getMergedTraits();
        const name =
          ns.isMemberSchema() && !traits.httpPayload
            ? (ns.getMemberTraits().xmlName ?? ns.getMemberName())
            : (traits.xmlName ?? ns.getName());
        if (!name || !ns.isStructSchema()) {
          throw new Error(
            `@aws-sdk/core/protocols - xml serializer, cannot write struct with empty name or non-struct, schema=${ns.getName(true)}.`,
          );
        }
        const structXmlNode = xmlBuilder.XmlNode.of(name);
        const [xmlnsAttr, xmlns] = this.getXmlnsAttribute(ns, parentXmlns);
        for (const [memberName, memberSchema] of ns.structIterator()) {
          const val = value[memberName];
          if (val != null || memberSchema.isIdempotencyToken()) {
            if (memberSchema.getMergedTraits().xmlAttribute) {
              structXmlNode.addAttribute(
                memberSchema.getMergedTraits().xmlName ?? memberName,
                this.writeSimple(memberSchema, val),
              );
              continue;
            }
            if (memberSchema.isListSchema()) {
              this.writeList(memberSchema, val, structXmlNode, xmlns);
            } else if (memberSchema.isMapSchema()) {
              this.writeMap(memberSchema, val, structXmlNode, xmlns);
            } else if (memberSchema.isStructSchema()) {
              structXmlNode.addChildNode(
                this.writeStruct(memberSchema, val, xmlns),
              );
            } else {
              const memberNode = xmlBuilder.XmlNode.of(
                memberSchema.getMergedTraits().xmlName ??
                  memberSchema.getMemberName(),
              );
              this.writeSimpleInto(memberSchema, val, memberNode, xmlns);
              structXmlNode.addChildNode(memberNode);
            }
          }
        }
        if (xmlns) {
          structXmlNode.addAttribute(xmlnsAttr, xmlns);
        }
        return structXmlNode;
      }
      writeList(listMember, array, container, parentXmlns) {
        if (!listMember.isMemberSchema()) {
          throw new Error(
            `@aws-sdk/core/protocols - xml serializer, cannot write non-member list: ${listMember.getName(true)}`,
          );
        }
        const listTraits = listMember.getMergedTraits();
        const listValueSchema = listMember.getValueSchema();
        const listValueTraits = listValueSchema.getMergedTraits();
        const sparse = !!listValueTraits.sparse;
        const flat = !!listTraits.xmlFlattened;
        const [xmlnsAttr, xmlns] = this.getXmlnsAttribute(
          listMember,
          parentXmlns,
        );
        const writeItem = (container, value) => {
          if (listValueSchema.isListSchema()) {
            this.writeList(
              listValueSchema,
              Array.isArray(value) ? value : [value],
              container,
              xmlns,
            );
          } else if (listValueSchema.isMapSchema()) {
            this.writeMap(listValueSchema, value, container, xmlns);
          } else if (listValueSchema.isStructSchema()) {
            const struct = this.writeStruct(listValueSchema, value, xmlns);
            container.addChildNode(
              struct.withName(
                flat
                  ? (listTraits.xmlName ?? listMember.getMemberName())
                  : (listValueTraits.xmlName ?? "member"),
              ),
            );
          } else {
            const listItemNode = xmlBuilder.XmlNode.of(
              flat
                ? (listTraits.xmlName ?? listMember.getMemberName())
                : (listValueTraits.xmlName ?? "member"),
            );
            this.writeSimpleInto(listValueSchema, value, listItemNode, xmlns);
            container.addChildNode(listItemNode);
          }
        };
        if (flat) {
          for (const value of array) {
            if (sparse || value != null) {
              writeItem(container, value);
            }
          }
        } else {
          const listNode = xmlBuilder.XmlNode.of(
            listTraits.xmlName ?? listMember.getMemberName(),
          );
          if (xmlns) {
            listNode.addAttribute(xmlnsAttr, xmlns);
          }
          for (const value of array) {
            if (sparse || value != null) {
              writeItem(listNode, value);
            }
          }
          container.addChildNode(listNode);
        }
      }
      writeMap(mapMember, map, container, parentXmlns, containerIsMap = false) {
        if (!mapMember.isMemberSchema()) {
          throw new Error(
            `@aws-sdk/core/protocols - xml serializer, cannot write non-member map: ${mapMember.getName(true)}`,
          );
        }
        const mapTraits = mapMember.getMergedTraits();
        const mapKeySchema = mapMember.getKeySchema();
        const mapKeyTraits = mapKeySchema.getMergedTraits();
        const keyTag = mapKeyTraits.xmlName ?? "key";
        const mapValueSchema = mapMember.getValueSchema();
        const mapValueTraits = mapValueSchema.getMergedTraits();
        const valueTag = mapValueTraits.xmlName ?? "value";
        const sparse = !!mapValueTraits.sparse;
        const flat = !!mapTraits.xmlFlattened;
        const [xmlnsAttr, xmlns] = this.getXmlnsAttribute(
          mapMember,
          parentXmlns,
        );
        const addKeyValue = (entry, key, val) => {
          const keyNode = xmlBuilder.XmlNode.of(keyTag, key);
          const [keyXmlnsAttr, keyXmlns] = this.getXmlnsAttribute(
            mapKeySchema,
            xmlns,
          );
          if (keyXmlns) {
            keyNode.addAttribute(keyXmlnsAttr, keyXmlns);
          }
          entry.addChildNode(keyNode);
          let valueNode = xmlBuilder.XmlNode.of(valueTag);
          if (mapValueSchema.isListSchema()) {
            this.writeList(mapValueSchema, val, valueNode, xmlns);
          } else if (mapValueSchema.isMapSchema()) {
            this.writeMap(mapValueSchema, val, valueNode, xmlns, true);
          } else if (mapValueSchema.isStructSchema()) {
            valueNode = this.writeStruct(mapValueSchema, val, xmlns);
          } else {
            this.writeSimpleInto(mapValueSchema, val, valueNode, xmlns);
          }
          entry.addChildNode(valueNode);
        };
        if (flat) {
          for (const [key, val] of Object.entries(map)) {
            if (sparse || val != null) {
              const entry = xmlBuilder.XmlNode.of(
                mapTraits.xmlName ?? mapMember.getMemberName(),
              );
              addKeyValue(entry, key, val);
              container.addChildNode(entry);
            }
          }
        } else {
          let mapNode;
          if (!containerIsMap) {
            mapNode = xmlBuilder.XmlNode.of(
              mapTraits.xmlName ?? mapMember.getMemberName(),
            );
            if (xmlns) {
              mapNode.addAttribute(xmlnsAttr, xmlns);
            }
            container.addChildNode(mapNode);
          }
          for (const [key, val] of Object.entries(map)) {
            if (sparse || val != null) {
              const entry = xmlBuilder.XmlNode.of("entry");
              addKeyValue(entry, key, val);
              (containerIsMap ? container : mapNode).addChildNode(entry);
            }
          }
        }
      }
      writeSimple(_schema, value) {
        if (null === value) {
          throw new Error(
            "@aws-sdk/core/protocols - (XML serializer) cannot write null value.",
          );
        }
        const ns = schema.NormalizedSchema.of(_schema);
        let nodeContents = null;
        if (value && typeof value === "object") {
          if (ns.isBlobSchema()) {
            nodeContents = (
              this.serdeContext?.base64Encoder ?? utilBase64.toBase64
            )(value);
          } else if (ns.isTimestampSchema() && value instanceof Date) {
            const format = protocols.determineTimestampFormat(
              ns,
              this.settings,
            );
            switch (format) {
              case 5:
                nodeContents = value.toISOString().replace(".000Z", "Z");
                break;
              case 6:
                nodeContents = smithyClient.dateToUtcString(value);
                break;
              case 7:
                nodeContents = String(value.getTime() / 1000);
                break;
              default:
                console.warn(
                  "Missing timestamp format, using http date",
                  value,
                );
                nodeContents = smithyClient.dateToUtcString(value);
                break;
            }
          } else if (ns.isBigDecimalSchema() && value) {
            if (value instanceof serde.NumericValue) {
              return value.string;
            }
            return String(value);
          } else if (ns.isMapSchema() || ns.isListSchema()) {
            throw new Error(
              "@aws-sdk/core/protocols - xml serializer, cannot call _write() on List/Map schema, call writeList or writeMap() instead.",
            );
          } else {
            throw new Error(
              `@aws-sdk/core/protocols - xml serializer, unhandled schema type for object value and schema: ${ns.getName(true)}`,
            );
          }
        }
        if (
          ns.isBooleanSchema() ||
          ns.isNumericSchema() ||
          ns.isBigIntegerSchema() ||
          ns.isBigDecimalSchema()
        ) {
          nodeContents = String(value);
        }
        if (ns.isStringSchema()) {
          if (value === undefined && ns.isIdempotencyToken()) {
            nodeContents = serde.generateIdempotencyToken();
          } else {
            nodeContents = String(value);
          }
        }
        if (nodeContents === null) {
          throw new Error(
            `Unhandled schema-value pair ${ns.getName(true)}=${value}`,
          );
        }
        return nodeContents;
      }
      writeSimpleInto(_schema, value, into, parentXmlns) {
        const nodeContents = this.writeSimple(_schema, value);
        const ns = schema.NormalizedSchema.of(_schema);
        const content = new xmlBuilder.XmlText(nodeContents);
        const [xmlnsAttr, xmlns] = this.getXmlnsAttribute(ns, parentXmlns);
        if (xmlns) {
          into.addAttribute(xmlnsAttr, xmlns);
        }
        into.addChildNode(content);
      }
      getXmlnsAttribute(ns, parentXmlns) {
        const traits = ns.getMergedTraits();
        const [prefix, xmlns] = traits.xmlNamespace ?? [];
        if (xmlns && xmlns !== parentXmlns) {
          return [prefix ? `xmlns:${prefix}` : "xmlns", xmlns];
        }
        return [void 0, void 0];
      }
    }

    class XmlCodec extends SerdeContextConfig {
      settings;
      constructor(settings) {
        super();
        this.settings = settings;
      }
      createSerializer() {
        const serializer = new XmlShapeSerializer(this.settings);
        serializer.setSerdeContext(this.serdeContext);
        return serializer;
      }
      createDeserializer() {
        const deserializer = new XmlShapeDeserializer(this.settings);
        deserializer.setSerdeContext(this.serdeContext);
        return deserializer;
      }
    }

    class AwsRestXmlProtocol extends protocols.HttpBindingProtocol {
      codec;
      serializer;
      deserializer;
      mixin = new ProtocolLib();
      constructor(options) {
        super(options);
        const settings = {
          timestampFormat: {
            useTrait: true,
            default: 5,
          },
          httpBindings: true,
          xmlNamespace: options.xmlNamespace,
          serviceNamespace: options.defaultNamespace,
        };
        this.codec = new XmlCodec(settings);
        this.serializer = new protocols.HttpInterceptingShapeSerializer(
          this.codec.createSerializer(),
          settings,
        );
        this.deserializer = new protocols.HttpInterceptingShapeDeserializer(
          this.codec.createDeserializer(),
          settings,
        );
      }
      getPayloadCodec() {
        return this.codec;
      }
      getShapeId() {
        return "aws.protocols#restXml";
      }
      async serializeRequest(operationSchema, input, context) {
        const request = await super.serializeRequest(
          operationSchema,
          input,
          context,
        );
        const inputSchema = schema.NormalizedSchema.of(operationSchema.input);
        if (!request.headers["content-type"]) {
          const contentType = this.mixin.resolveRestContentType(
            this.getDefaultContentType(),
            inputSchema,
          );
          if (contentType) {
            request.headers["content-type"] = contentType;
          }
        }
        if (request.headers["content-type"] === this.getDefaultContentType()) {
          if (typeof request.body === "string") {
            request.body =
              '<?xml version="1.0" encoding="UTF-8"?>' + request.body;
          }
        }
        return request;
      }
      async deserializeResponse(operationSchema, context, response) {
        return super.deserializeResponse(operationSchema, context, response);
      }
      async handleError(
        operationSchema,
        context,
        response,
        dataObject,
        metadata,
      ) {
        const errorIdentifier =
          loadRestXmlErrorCode(response, dataObject) ?? "Unknown";
        const { errorSchema, errorMetadata } =
          await this.mixin.getErrorSchemaOrThrowBaseException(
            errorIdentifier,
            this.options.defaultNamespace,
            response,
            dataObject,
            metadata,
          );
        const ns = schema.NormalizedSchema.of(errorSchema);
        const message =
          dataObject.Error?.message ??
          dataObject.Error?.Message ??
          dataObject.message ??
          dataObject.Message ??
          "Unknown";
        const ErrorCtor =
          schema.TypeRegistry.for(errorSchema[1]).getErrorCtor(errorSchema) ??
          Error;
        const exception = new ErrorCtor(message);
        await this.deserializeHttpMessage(
          errorSchema,
          context,
          response,
          dataObject,
        );
        const output = {};
        for (const [name, member] of ns.structIterator()) {
          const target = member.getMergedTraits().xmlName ?? name;
          const value = dataObject.Error?.[target] ?? dataObject[target];
          output[name] = this.codec
            .createDeserializer()
            .readSchema(member, value);
        }
        throw this.mixin.decorateServiceException(
          Object.assign(
            exception,
            errorMetadata,
            {
              $fault: ns.getMergedTraits().error,
              message,
            },
            output,
          ),
          dataObject,
        );
      }
      getDefaultContentType() {
        return "application/xml";
      }
    }

    exports.AWSSDKSigV4Signer = AWSSDKSigV4Signer;
    exports.AwsEc2QueryProtocol = AwsEc2QueryProtocol;
    exports.AwsJson1_0Protocol = AwsJson1_0Protocol;
    exports.AwsJson1_1Protocol = AwsJson1_1Protocol;
    exports.AwsJsonRpcProtocol = AwsJsonRpcProtocol;
    exports.AwsQueryProtocol = AwsQueryProtocol;
    exports.AwsRestJsonProtocol = AwsRestJsonProtocol;
    exports.AwsRestXmlProtocol = AwsRestXmlProtocol;
    exports.AwsSdkSigV4ASigner = AwsSdkSigV4ASigner;
    exports.AwsSdkSigV4Signer = AwsSdkSigV4Signer;
    exports.AwsSmithyRpcV2CborProtocol = AwsSmithyRpcV2CborProtocol;
    exports.JsonCodec = JsonCodec;
    exports.JsonShapeDeserializer = JsonShapeDeserializer;
    exports.JsonShapeSerializer = JsonShapeSerializer;
    exports.NODE_AUTH_SCHEME_PREFERENCE_OPTIONS =
      NODE_AUTH_SCHEME_PREFERENCE_OPTIONS;
    exports.NODE_SIGV4A_CONFIG_OPTIONS = NODE_SIGV4A_CONFIG_OPTIONS;
    exports.XmlCodec = XmlCodec;
    exports.XmlShapeDeserializer = XmlShapeDeserializer;
    exports.XmlShapeSerializer = XmlShapeSerializer;
    exports._toBool = _toBool;
    exports._toNum = _toNum;
    exports._toStr = _toStr;
    exports.awsExpectUnion = awsExpectUnion;
    exports.emitWarningIfUnsupportedVersion = emitWarningIfUnsupportedVersion;
    exports.getBearerTokenEnvKey = getBearerTokenEnvKey;
    exports.loadRestJsonErrorCode = loadRestJsonErrorCode;
    exports.loadRestXmlErrorCode = loadRestXmlErrorCode;
    exports.parseJsonBody = parseJsonBody;
    exports.parseJsonErrorBody = parseJsonErrorBody;
    exports.parseXmlBody = parseXmlBody;
    exports.parseXmlErrorBody = parseXmlErrorBody;
    exports.resolveAWSSDKSigV4Config = resolveAWSSDKSigV4Config;
    exports.resolveAwsSdkSigV4AConfig = resolveAwsSdkSigV4AConfig;
    exports.resolveAwsSdkSigV4Config = resolveAwsSdkSigV4Config;
    exports.setCredentialFeature = setCredentialFeature;
    exports.setFeature = setFeature;
    exports.setTokenFeature = setTokenFeature;
    exports.state = state;
    exports.validateSigningProperties = validateSigningProperties;

    /***/
  },

  /***/ 5222: /***/ (__unused_webpack_module, exports, __webpack_require__) => {
    var cbor = __webpack_require__(4645);
    var schema = __webpack_require__(6890);
    var smithyClient = __webpack_require__(1411);
    var protocols = __webpack_require__(3422);
    var serde = __webpack_require__(2430);
    var utilBase64 = __webpack_require__(8385);
    var utilUtf8 = __webpack_require__(1577);
    var xmlBuilder = __webpack_require__(7660);

    class ProtocolLib {
      queryCompat;
      constructor(queryCompat = false) {
        this.queryCompat = queryCompat;
      }
      resolveRestContentType(defaultContentType, inputSchema) {
        const members = inputSchema.getMemberSchemas();
        const httpPayloadMember = Object.values(members).find((m) => {
          return !!m.getMergedTraits().httpPayload;
        });
        if (httpPayloadMember) {
          const mediaType = httpPayloadMember.getMergedTraits().mediaType;
          if (mediaType) {
            return mediaType;
          } else if (httpPayloadMember.isStringSchema()) {
            return "text/plain";
          } else if (httpPayloadMember.isBlobSchema()) {
            return "application/octet-stream";
          } else {
            return defaultContentType;
          }
        } else if (!inputSchema.isUnitSchema()) {
          const hasBody = Object.values(members).find((m) => {
            const {
              httpQuery,
              httpQueryParams,
              httpHeader,
              httpLabel,
              httpPrefixHeaders,
            } = m.getMergedTraits();
            const noPrefixHeaders = httpPrefixHeaders === void 0;
            return (
              !httpQuery &&
              !httpQueryParams &&
              !httpHeader &&
              !httpLabel &&
              noPrefixHeaders
            );
          });
          if (hasBody) {
            return defaultContentType;
          }
        }
      }
      async getErrorSchemaOrThrowBaseException(
        errorIdentifier,
        defaultNamespace,
        response,
        dataObject,
        metadata,
        getErrorSchema,
      ) {
        let namespace = defaultNamespace;
        let errorName = errorIdentifier;
        if (errorIdentifier.includes("#")) {
          [namespace, errorName] = errorIdentifier.split("#");
        }
        const errorMetadata = {
          $metadata: metadata,
          $fault: response.statusCode < 500 ? "client" : "server",
        };
        const registry = schema.TypeRegistry.for(namespace);
        try {
          const errorSchema =
            getErrorSchema?.(registry, errorName) ??
            registry.getSchema(errorIdentifier);
          return { errorSchema, errorMetadata };
        } catch (e) {
          dataObject.message =
            dataObject.message ?? dataObject.Message ?? "UnknownError";
          const synthetic = schema.TypeRegistry.for(
            "smithy.ts.sdk.synthetic." + namespace,
          );
          const baseExceptionSchema = synthetic.getBaseException();
          if (baseExceptionSchema) {
            const ErrorCtor =
              synthetic.getErrorCtor(baseExceptionSchema) ?? Error;
            throw this.decorateServiceException(
              Object.assign(new ErrorCtor({ name: errorName }), errorMetadata),
              dataObject,
            );
          }
          throw this.decorateServiceException(
            Object.assign(new Error(errorName), errorMetadata),
            dataObject,
          );
        }
      }
      decorateServiceException(exception, additions = {}) {
        if (this.queryCompat) {
          const msg = exception.Message ?? additions.Message;
          const error = smithyClient.decorateServiceException(
            exception,
            additions,
          );
          if (msg) {
            error.Message = msg;
            error.message = msg;
          }
          return error;
        }
        return smithyClient.decorateServiceException(exception, additions);
      }
      setQueryCompatError(output, response) {
        const queryErrorHeader = response.headers?.["x-amzn-query-error"];
        if (output !== undefined && queryErrorHeader != null) {
          const [Code, Type] = queryErrorHeader.split(";");
          const entries = Object.entries(output);
          const Error = {
            Code,
            Type,
          };
          Object.assign(output, Error);
          for (const [k, v] of entries) {
            Error[k] = v;
          }
          delete Error.__type;
          output.Error = Error;
        }
      }
      queryCompatOutput(queryCompatErrorData, errorData) {
        if (queryCompatErrorData.Error) {
          errorData.Error = queryCompatErrorData.Error;
        }
        if (queryCompatErrorData.Type) {
          errorData.Type = queryCompatErrorData.Type;
        }
        if (queryCompatErrorData.Code) {
          errorData.Code = queryCompatErrorData.Code;
        }
      }
    }

    class AwsSmithyRpcV2CborProtocol extends cbor.SmithyRpcV2CborProtocol {
      awsQueryCompatible;
      mixin;
      constructor({ defaultNamespace, awsQueryCompatible }) {
        super({ defaultNamespace });
        this.awsQueryCompatible = !!awsQueryCompatible;
        this.mixin = new ProtocolLib(this.awsQueryCompatible);
      }
      async serializeRequest(operationSchema, input, context) {
        const request = await super.serializeRequest(
          operationSchema,
          input,
          context,
        );
        if (this.awsQueryCompatible) {
          request.headers["x-amzn-query-mode"] = "true";
        }
        return request;
      }
      async handleError(
        operationSchema,
        context,
        response,
        dataObject,
        metadata,
      ) {
        if (this.awsQueryCompatible) {
          this.mixin.setQueryCompatError(dataObject, response);
        }
        const errorName =
          cbor.loadSmithyRpcV2CborErrorCode(response, dataObject) ?? "Unknown";
        const { errorSchema, errorMetadata } =
          await this.mixin.getErrorSchemaOrThrowBaseException(
            errorName,
            this.options.defaultNamespace,
            response,
            dataObject,
            metadata,
          );
        const ns = schema.NormalizedSchema.of(errorSchema);
        const message = dataObject.message ?? dataObject.Message ?? "Unknown";
        const ErrorCtor =
          schema.TypeRegistry.for(errorSchema[1]).getErrorCtor(errorSchema) ??
          Error;
        const exception = new ErrorCtor(message);
        const output = {};
        for (const [name, member] of ns.structIterator()) {
          output[name] = this.deserializer.readValue(member, dataObject[name]);
        }
        if (this.awsQueryCompatible) {
          this.mixin.queryCompatOutput(dataObject, output);
        }
        throw this.mixin.decorateServiceException(
          Object.assign(
            exception,
            errorMetadata,
            {
              $fault: ns.getMergedTraits().error,
              message,
            },
            output,
          ),
          dataObject,
        );
      }
    }

    const _toStr = (val) => {
      if (val == null) {
        return val;
      }
      if (typeof val === "number" || typeof val === "bigint") {
        const warning = new Error(
          `Received number ${val} where a string was expected.`,
        );
        warning.name = "Warning";
        console.warn(warning);
        return String(val);
      }
      if (typeof val === "boolean") {
        const warning = new Error(
          `Received boolean ${val} where a string was expected.`,
        );
        warning.name = "Warning";
        console.warn(warning);
        return String(val);
      }
      return val;
    };
    const _toBool = (val) => {
      if (val == null) {
        return val;
      }
      if (typeof val === "string") {
        const lowercase = val.toLowerCase();
        if (val !== "" && lowercase !== "false" && lowercase !== "true") {
          const warning = new Error(
            `Received string "${val}" where a boolean was expected.`,
          );
          warning.name = "Warning";
          console.warn(warning);
        }
        return val !== "" && lowercase !== "false";
      }
      return val;
    };
    const _toNum = (val) => {
      if (val == null) {
        return val;
      }
      if (typeof val === "string") {
        const num = Number(val);
        if (num.toString() !== val) {
          const warning = new Error(
            `Received string "${val}" where a number was expected.`,
          );
          warning.name = "Warning";
          console.warn(warning);
          return val;
        }
        return num;
      }
      return val;
    };

    class SerdeContextConfig {
      serdeContext;
      setSerdeContext(serdeContext) {
        this.serdeContext = serdeContext;
      }
    }

    function jsonReviver(key, value, context) {
      if (context?.source) {
        const numericString = context.source;
        if (typeof value === "number") {
          if (
            value > Number.MAX_SAFE_INTEGER ||
            value < Number.MIN_SAFE_INTEGER ||
            numericString !== String(value)
          ) {
            const isFractional = numericString.includes(".");
            if (isFractional) {
              return new serde.NumericValue(numericString, "bigDecimal");
            } else {
              return BigInt(numericString);
            }
          }
        }
      }
      return value;
    }

    const collectBodyString = (streamBody, context) =>
      smithyClient
        .collectBody(streamBody, context)
        .then((body) => (context?.utf8Encoder ?? utilUtf8.toUtf8)(body));

    const parseJsonBody = (streamBody, context) =>
      collectBodyString(streamBody, context).then((encoded) => {
        if (encoded.length) {
          try {
            return JSON.parse(encoded);
          } catch (e) {
            if (e?.name === "SyntaxError") {
              Object.defineProperty(e, "$responseBodyText", {
                value: encoded,
              });
            }
            throw e;
          }
        }
        return {};
      });
    const parseJsonErrorBody = async (errorBody, context) => {
      const value = await parseJsonBody(errorBody, context);
      value.message = value.message ?? value.Message;
      return value;
    };
    const loadRestJsonErrorCode = (output, data) => {
      const findKey = (object, key) =>
        Object.keys(object).find((k) => k.toLowerCase() === key.toLowerCase());
      const sanitizeErrorCode = (rawValue) => {
        let cleanValue = rawValue;
        if (typeof cleanValue === "number") {
          cleanValue = cleanValue.toString();
        }
        if (cleanValue.indexOf(",") >= 0) {
          cleanValue = cleanValue.split(",")[0];
        }
        if (cleanValue.indexOf(":") >= 0) {
          cleanValue = cleanValue.split(":")[0];
        }
        if (cleanValue.indexOf("#") >= 0) {
          cleanValue = cleanValue.split("#")[1];
        }
        return cleanValue;
      };
      const headerKey = findKey(output.headers, "x-amzn-errortype");
      if (headerKey !== undefined) {
        return sanitizeErrorCode(output.headers[headerKey]);
      }
      if (data && typeof data === "object") {
        const codeKey = findKey(data, "code");
        if (codeKey && data[codeKey] !== undefined) {
          return sanitizeErrorCode(data[codeKey]);
        }
        if (data["__type"] !== undefined) {
          return sanitizeErrorCode(data["__type"]);
        }
      }
    };

    class JsonShapeDeserializer extends SerdeContextConfig {
      settings;
      constructor(settings) {
        super();
        this.settings = settings;
      }
      async read(schema, data) {
        return this._read(
          schema,
          typeof data === "string"
            ? JSON.parse(data, jsonReviver)
            : await parseJsonBody(data, this.serdeContext),
        );
      }
      readObject(schema, data) {
        return this._read(schema, data);
      }
      _read(schema$1, value) {
        const isObject = value !== null && typeof value === "object";
        const ns = schema.NormalizedSchema.of(schema$1);
        if (ns.isListSchema() && Array.isArray(value)) {
          const listMember = ns.getValueSchema();
          const out = [];
          const sparse = !!ns.getMergedTraits().sparse;
          for (const item of value) {
            if (sparse || item != null) {
              out.push(this._read(listMember, item));
            }
          }
          return out;
        } else if (ns.isMapSchema() && isObject) {
          const mapMember = ns.getValueSchema();
          const out = {};
          const sparse = !!ns.getMergedTraits().sparse;
          for (const [_k, _v] of Object.entries(value)) {
            if (sparse || _v != null) {
              out[_k] = this._read(mapMember, _v);
            }
          }
          return out;
        } else if (ns.isStructSchema() && isObject) {
          const out = {};
          for (const [memberName, memberSchema] of ns.structIterator()) {
            const fromKey = this.settings.jsonName
              ? (memberSchema.getMergedTraits().jsonName ?? memberName)
              : memberName;
            const deserializedValue = this._read(memberSchema, value[fromKey]);
            if (deserializedValue != null) {
              out[memberName] = deserializedValue;
            }
          }
          return out;
        }
        if (ns.isBlobSchema() && typeof value === "string") {
          return utilBase64.fromBase64(value);
        }
        const mediaType = ns.getMergedTraits().mediaType;
        if (ns.isStringSchema() && typeof value === "string" && mediaType) {
          const isJson =
            mediaType === "application/json" || mediaType.endsWith("+json");
          if (isJson) {
            return serde.LazyJsonString.from(value);
          }
        }
        if (ns.isTimestampSchema() && value != null) {
          const format = protocols.determineTimestampFormat(ns, this.settings);
          switch (format) {
            case 5:
              return serde.parseRfc3339DateTimeWithOffset(value);
            case 6:
              return serde.parseRfc7231DateTime(value);
            case 7:
              return serde.parseEpochTimestamp(value);
            default:
              console.warn(
                "Missing timestamp format, parsing value with Date constructor:",
                value,
              );
              return new Date(value);
          }
        }
        if (
          ns.isBigIntegerSchema() &&
          (typeof value === "number" || typeof value === "string")
        ) {
          return BigInt(value);
        }
        if (ns.isBigDecimalSchema() && value != undefined) {
          if (value instanceof serde.NumericValue) {
            return value;
          }
          const untyped = value;
          if (untyped.type === "bigDecimal" && "string" in untyped) {
            return new serde.NumericValue(untyped.string, untyped.type);
          }
          return new serde.NumericValue(String(value), "bigDecimal");
        }
        if (ns.isNumericSchema() && typeof value === "string") {
          switch (value) {
            case "Infinity":
              return Infinity;
            case "-Infinity":
              return -Infinity;
            case "NaN":
              return NaN;
          }
        }
        if (ns.isDocumentSchema()) {
          if (isObject) {
            const out = Array.isArray(value) ? [] : {};
            for (const [k, v] of Object.entries(value)) {
              if (v instanceof serde.NumericValue) {
                out[k] = v;
              } else {
                out[k] = this._read(ns, v);
              }
            }
            return out;
          } else {
            return structuredClone(value);
          }
        }
        return value;
      }
    }

    const NUMERIC_CONTROL_CHAR = String.fromCharCode(925);
    class JsonReplacer {
      values = new Map();
      counter = 0;
      stage = 0;
      createReplacer() {
        if (this.stage === 1) {
          throw new Error(
            "@aws-sdk/core/protocols - JsonReplacer already created.",
          );
        }
        if (this.stage === 2) {
          throw new Error("@aws-sdk/core/protocols - JsonReplacer exhausted.");
        }
        this.stage = 1;
        return (key, value) => {
          if (value instanceof serde.NumericValue) {
            const v =
              `${NUMERIC_CONTROL_CHAR + "nv" + this.counter++}_` + value.string;
            this.values.set(`"${v}"`, value.string);
            return v;
          }
          if (typeof value === "bigint") {
            const s = value.toString();
            const v = `${NUMERIC_CONTROL_CHAR + "b" + this.counter++}_` + s;
            this.values.set(`"${v}"`, s);
            return v;
          }
          return value;
        };
      }
      replaceInJson(json) {
        if (this.stage === 0) {
          throw new Error(
            "@aws-sdk/core/protocols - JsonReplacer not created yet.",
          );
        }
        if (this.stage === 2) {
          throw new Error("@aws-sdk/core/protocols - JsonReplacer exhausted.");
        }
        this.stage = 2;
        if (this.counter === 0) {
          return json;
        }
        for (const [key, value] of this.values) {
          json = json.replace(key, value);
        }
        return json;
      }
    }

    class JsonShapeSerializer extends SerdeContextConfig {
      settings;
      buffer;
      rootSchema;
      constructor(settings) {
        super();
        this.settings = settings;
      }
      write(schema$1, value) {
        this.rootSchema = schema.NormalizedSchema.of(schema$1);
        this.buffer = this._write(this.rootSchema, value);
      }
      writeDiscriminatedDocument(schema$1, value) {
        this.write(schema$1, value);
        if (typeof this.buffer === "object") {
          this.buffer.__type =
            schema.NormalizedSchema.of(schema$1).getName(true);
        }
      }
      flush() {
        const { rootSchema } = this;
        this.rootSchema = undefined;
        if (rootSchema?.isStructSchema() || rootSchema?.isDocumentSchema()) {
          const replacer = new JsonReplacer();
          return replacer.replaceInJson(
            JSON.stringify(this.buffer, replacer.createReplacer(), 0),
          );
        }
        return this.buffer;
      }
      _write(schema$1, value, container) {
        const isObject = value !== null && typeof value === "object";
        const ns = schema.NormalizedSchema.of(schema$1);
        if (ns.isListSchema() && Array.isArray(value)) {
          const listMember = ns.getValueSchema();
          const out = [];
          const sparse = !!ns.getMergedTraits().sparse;
          for (const item of value) {
            if (sparse || item != null) {
              out.push(this._write(listMember, item));
            }
          }
          return out;
        } else if (ns.isMapSchema() && isObject) {
          const mapMember = ns.getValueSchema();
          const out = {};
          const sparse = !!ns.getMergedTraits().sparse;
          for (const [_k, _v] of Object.entries(value)) {
            if (sparse || _v != null) {
              out[_k] = this._write(mapMember, _v);
            }
          }
          return out;
        } else if (ns.isStructSchema() && isObject) {
          const out = {};
          for (const [memberName, memberSchema] of ns.structIterator()) {
            const targetKey = this.settings.jsonName
              ? (memberSchema.getMergedTraits().jsonName ?? memberName)
              : memberName;
            const serializableValue = this._write(
              memberSchema,
              value[memberName],
              ns,
            );
            if (serializableValue !== undefined) {
              out[targetKey] = serializableValue;
            }
          }
          return out;
        }
        if (value === null && container?.isStructSchema()) {
          return void 0;
        }
        if (
          (ns.isBlobSchema() &&
            (value instanceof Uint8Array || typeof value === "string")) ||
          (ns.isDocumentSchema() && value instanceof Uint8Array)
        ) {
          if (ns === this.rootSchema) {
            return value;
          }
          return (this.serdeContext?.base64Encoder ?? utilBase64.toBase64)(
            value,
          );
        }
        if (
          (ns.isTimestampSchema() || ns.isDocumentSchema()) &&
          value instanceof Date
        ) {
          const format = protocols.determineTimestampFormat(ns, this.settings);
          switch (format) {
            case 5:
              return value.toISOString().replace(".000Z", "Z");
            case 6:
              return serde.dateToUtcString(value);
            case 7:
              return value.getTime() / 1000;
            default:
              console.warn(
                "Missing timestamp format, using epoch seconds",
                value,
              );
              return value.getTime() / 1000;
          }
        }
        if (ns.isNumericSchema() && typeof value === "number") {
          if (Math.abs(value) === Infinity || isNaN(value)) {
            return String(value);
          }
        }
        if (ns.isStringSchema()) {
          if (typeof value === "undefined" && ns.isIdempotencyToken()) {
            return serde.generateIdempotencyToken();
          }
          const mediaType = ns.getMergedTraits().mediaType;
          if (value != null && mediaType) {
            const isJson =
              mediaType === "application/json" || mediaType.endsWith("+json");
            if (isJson) {
              return serde.LazyJsonString.from(value);
            }
          }
        }
        if (ns.isDocumentSchema()) {
          if (isObject) {
            const out = Array.isArray(value) ? [] : {};
            for (const [k, v] of Object.entries(value)) {
              if (v instanceof serde.NumericValue) {
                out[k] = v;
              } else {
                out[k] = this._write(ns, v);
              }
            }
            return out;
          } else {
            return structuredClone(value);
          }
        }
        return value;
      }
    }

    class JsonCodec extends SerdeContextConfig {
      settings;
      constructor(settings) {
        super();
        this.settings = settings;
      }
      createSerializer() {
        const serializer = new JsonShapeSerializer(this.settings);
        serializer.setSerdeContext(this.serdeContext);
        return serializer;
      }
      createDeserializer() {
        const deserializer = new JsonShapeDeserializer(this.settings);
        deserializer.setSerdeContext(this.serdeContext);
        return deserializer;
      }
    }

    class AwsJsonRpcProtocol extends protocols.RpcProtocol {
      serializer;
      deserializer;
      serviceTarget;
      codec;
      mixin;
      awsQueryCompatible;
      constructor({ defaultNamespace, serviceTarget, awsQueryCompatible }) {
        super({
          defaultNamespace,
        });
        this.serviceTarget = serviceTarget;
        this.codec = new JsonCodec({
          timestampFormat: {
            useTrait: true,
            default: 7,
          },
          jsonName: false,
        });
        this.serializer = this.codec.createSerializer();
        this.deserializer = this.codec.createDeserializer();
        this.awsQueryCompatible = !!awsQueryCompatible;
        this.mixin = new ProtocolLib(this.awsQueryCompatible);
      }
      async serializeRequest(operationSchema, input, context) {
        const request = await super.serializeRequest(
          operationSchema,
          input,
          context,
        );
        if (!request.path.endsWith("/")) {
          request.path += "/";
        }
        Object.assign(request.headers, {
          "content-type": `application/x-amz-json-${this.getJsonRpcVersion()}`,
          "x-amz-target": `${this.serviceTarget}.${operationSchema.name}`,
        });
        if (this.awsQueryCompatible) {
          request.headers["x-amzn-query-mode"] = "true";
        }
        if (schema.deref(operationSchema.input) === "unit" || !request.body) {
          request.body = "{}";
        }
        return request;
      }
      getPayloadCodec() {
        return this.codec;
      }
      async handleError(
        operationSchema,
        context,
        response,
        dataObject,
        metadata,
      ) {
        if (this.awsQueryCompatible) {
          this.mixin.setQueryCompatError(dataObject, response);
        }
        const errorIdentifier =
          loadRestJsonErrorCode(response, dataObject) ?? "Unknown";
        const { errorSchema, errorMetadata } =
          await this.mixin.getErrorSchemaOrThrowBaseException(
            errorIdentifier,
            this.options.defaultNamespace,
            response,
            dataObject,
            metadata,
          );
        const ns = schema.NormalizedSchema.of(errorSchema);
        const message = dataObject.message ?? dataObject.Message ?? "Unknown";
        const ErrorCtor =
          schema.TypeRegistry.for(errorSchema[1]).getErrorCtor(errorSchema) ??
          Error;
        const exception = new ErrorCtor(message);
        const output = {};
        for (const [name, member] of ns.structIterator()) {
          const target = member.getMergedTraits().jsonName ?? name;
          output[name] = this.codec
            .createDeserializer()
            .readObject(member, dataObject[target]);
        }
        if (this.awsQueryCompatible) {
          this.mixin.queryCompatOutput(dataObject, output);
        }
        throw this.mixin.decorateServiceException(
          Object.assign(
            exception,
            errorMetadata,
            {
              $fault: ns.getMergedTraits().error,
              message,
            },
            output,
          ),
          dataObject,
        );
      }
    }

    class AwsJson1_0Protocol extends AwsJsonRpcProtocol {
      constructor({ defaultNamespace, serviceTarget, awsQueryCompatible }) {
        super({
          defaultNamespace,
          serviceTarget,
          awsQueryCompatible,
        });
      }
      getShapeId() {
        return "aws.protocols#awsJson1_0";
      }
      getJsonRpcVersion() {
        return "1.0";
      }
      getDefaultContentType() {
        return "application/x-amz-json-1.0";
      }
    }

    class AwsJson1_1Protocol extends AwsJsonRpcProtocol {
      constructor({ defaultNamespace, serviceTarget, awsQueryCompatible }) {
        super({
          defaultNamespace,
          serviceTarget,
          awsQueryCompatible,
        });
      }
      getShapeId() {
        return "aws.protocols#awsJson1_1";
      }
      getJsonRpcVersion() {
        return "1.1";
      }
      getDefaultContentType() {
        return "application/x-amz-json-1.1";
      }
    }

    class AwsRestJsonProtocol extends protocols.HttpBindingProtocol {
      serializer;
      deserializer;
      codec;
      mixin = new ProtocolLib();
      constructor({ defaultNamespace }) {
        super({
          defaultNamespace,
        });
        const settings = {
          timestampFormat: {
            useTrait: true,
            default: 7,
          },
          httpBindings: true,
          jsonName: true,
        };
        this.codec = new JsonCodec(settings);
        this.serializer = new protocols.HttpInterceptingShapeSerializer(
          this.codec.createSerializer(),
          settings,
        );
        this.deserializer = new protocols.HttpInterceptingShapeDeserializer(
          this.codec.createDeserializer(),
          settings,
        );
      }
      getShapeId() {
        return "aws.protocols#restJson1";
      }
      getPayloadCodec() {
        return this.codec;
      }
      setSerdeContext(serdeContext) {
        this.codec.setSerdeContext(serdeContext);
        super.setSerdeContext(serdeContext);
      }
      async serializeRequest(operationSchema, input, context) {
        const request = await super.serializeRequest(
          operationSchema,
          input,
          context,
        );
        const inputSchema = schema.NormalizedSchema.of(operationSchema.input);
        if (!request.headers["content-type"]) {
          const contentType = this.mixin.resolveRestContentType(
            this.getDefaultContentType(),
            inputSchema,
          );
          if (contentType) {
            request.headers["content-type"] = contentType;
          }
        }
        if (
          request.body == null &&
          request.headers["content-type"] === this.getDefaultContentType()
        ) {
          request.body = "{}";
        }
        return request;
      }
      async deserializeResponse(operationSchema, context, response) {
        const output = await super.deserializeResponse(
          operationSchema,
          context,
          response,
        );
        const outputSchema = schema.NormalizedSchema.of(operationSchema.output);
        for (const [name, member] of outputSchema.structIterator()) {
          if (member.getMemberTraits().httpPayload && !(name in output)) {
            output[name] = null;
          }
        }
        return output;
      }
      async handleError(
        operationSchema,
        context,
        response,
        dataObject,
        metadata,
      ) {
        const errorIdentifier =
          loadRestJsonErrorCode(response, dataObject) ?? "Unknown";
        const { errorSchema, errorMetadata } =
          await this.mixin.getErrorSchemaOrThrowBaseException(
            errorIdentifier,
            this.options.defaultNamespace,
            response,
            dataObject,
            metadata,
          );
        const ns = schema.NormalizedSchema.of(errorSchema);
        const message = dataObject.message ?? dataObject.Message ?? "Unknown";
        const ErrorCtor =
          schema.TypeRegistry.for(errorSchema[1]).getErrorCtor(errorSchema) ??
          Error;
        const exception = new ErrorCtor(message);
        await this.deserializeHttpMessage(
          errorSchema,
          context,
          response,
          dataObject,
        );
        const output = {};
        for (const [name, member] of ns.structIterator()) {
          const target = member.getMergedTraits().jsonName ?? name;
          output[name] = this.codec
            .createDeserializer()
            .readObject(member, dataObject[target]);
        }
        throw this.mixin.decorateServiceException(
          Object.assign(
            exception,
            errorMetadata,
            {
              $fault: ns.getMergedTraits().error,
              message,
            },
            output,
          ),
          dataObject,
        );
      }
      getDefaultContentType() {
        return "application/json";
      }
    }

    const awsExpectUnion = (value) => {
      if (value == null) {
        return undefined;
      }
      if (typeof value === "object" && "__type" in value) {
        delete value.__type;
      }
      return smithyClient.expectUnion(value);
    };

    class XmlShapeDeserializer extends SerdeContextConfig {
      settings;
      stringDeserializer;
      constructor(settings) {
        super();
        this.settings = settings;
        this.stringDeserializer = new protocols.FromStringShapeDeserializer(
          settings,
        );
      }
      setSerdeContext(serdeContext) {
        this.serdeContext = serdeContext;
        this.stringDeserializer.setSerdeContext(serdeContext);
      }
      read(schema$1, bytes, key) {
        const ns = schema.NormalizedSchema.of(schema$1);
        const memberSchemas = ns.getMemberSchemas();
        const isEventPayload =
          ns.isStructSchema() &&
          ns.isMemberSchema() &&
          !!Object.values(memberSchemas).find((memberNs) => {
            return !!memberNs.getMemberTraits().eventPayload;
          });
        if (isEventPayload) {
          const output = {};
          const memberName = Object.keys(memberSchemas)[0];
          const eventMemberSchema = memberSchemas[memberName];
          if (eventMemberSchema.isBlobSchema()) {
            output[memberName] = bytes;
          } else {
            output[memberName] = this.read(memberSchemas[memberName], bytes);
          }
          return output;
        }
        const xmlString = (this.serdeContext?.utf8Encoder ?? utilUtf8.toUtf8)(
          bytes,
        );
        const parsedObject = this.parseXml(xmlString);
        return this.readSchema(
          schema$1,
          key ? parsedObject[key] : parsedObject,
        );
      }
      readSchema(_schema, value) {
        const ns = schema.NormalizedSchema.of(_schema);
        if (ns.isUnitSchema()) {
          return;
        }
        const traits = ns.getMergedTraits();
        if (ns.isListSchema() && !Array.isArray(value)) {
          return this.readSchema(ns, [value]);
        }
        if (value == null) {
          return value;
        }
        if (typeof value === "object") {
          const sparse = !!traits.sparse;
          const flat = !!traits.xmlFlattened;
          if (ns.isListSchema()) {
            const listValue = ns.getValueSchema();
            const buffer = [];
            const sourceKey = listValue.getMergedTraits().xmlName ?? "member";
            const source = flat ? value : (value[0] ?? value)[sourceKey];
            const sourceArray = Array.isArray(source) ? source : [source];
            for (const v of sourceArray) {
              if (v != null || sparse) {
                buffer.push(this.readSchema(listValue, v));
              }
            }
            return buffer;
          }
          const buffer = {};
          if (ns.isMapSchema()) {
            const keyNs = ns.getKeySchema();
            const memberNs = ns.getValueSchema();
            let entries;
            if (flat) {
              entries = Array.isArray(value) ? value : [value];
            } else {
              entries = Array.isArray(value.entry)
                ? value.entry
                : [value.entry];
            }
            const keyProperty = keyNs.getMergedTraits().xmlName ?? "key";
            const valueProperty = memberNs.getMergedTraits().xmlName ?? "value";
            for (const entry of entries) {
              const key = entry[keyProperty];
              const value = entry[valueProperty];
              if (value != null || sparse) {
                buffer[key] = this.readSchema(memberNs, value);
              }
            }
            return buffer;
          }
          if (ns.isStructSchema()) {
            for (const [memberName, memberSchema] of ns.structIterator()) {
              const memberTraits = memberSchema.getMergedTraits();
              const xmlObjectKey = !memberTraits.httpPayload
                ? (memberSchema.getMemberTraits().xmlName ?? memberName)
                : (memberTraits.xmlName ?? memberSchema.getName());
              if (value[xmlObjectKey] != null) {
                buffer[memberName] = this.readSchema(
                  memberSchema,
                  value[xmlObjectKey],
                );
              }
            }
            return buffer;
          }
          if (ns.isDocumentSchema()) {
            return value;
          }
          throw new Error(
            `@aws-sdk/core/protocols - xml deserializer unhandled schema type for ${ns.getName(true)}`,
          );
        }
        if (ns.isListSchema()) {
          return [];
        }
        if (ns.isMapSchema() || ns.isStructSchema()) {
          return {};
        }
        return this.stringDeserializer.read(ns, value);
      }
      parseXml(xml) {
        if (xml.length) {
          let parsedObj;
          try {
            parsedObj = xmlBuilder.parseXML(xml);
          } catch (e) {
            if (e && typeof e === "object") {
              Object.defineProperty(e, "$responseBodyText", {
                value: xml,
              });
            }
            throw e;
          }
          const textNodeName = "#text";
          const key = Object.keys(parsedObj)[0];
          const parsedObjToReturn = parsedObj[key];
          if (parsedObjToReturn[textNodeName]) {
            parsedObjToReturn[key] = parsedObjToReturn[textNodeName];
            delete parsedObjToReturn[textNodeName];
          }
          return smithyClient.getValueFromTextNode(parsedObjToReturn);
        }
        return {};
      }
    }

    class QueryShapeSerializer extends SerdeContextConfig {
      settings;
      buffer;
      constructor(settings) {
        super();
        this.settings = settings;
      }
      write(schema$1, value, prefix = "") {
        if (this.buffer === undefined) {
          this.buffer = "";
        }
        const ns = schema.NormalizedSchema.of(schema$1);
        if (prefix && !prefix.endsWith(".")) {
          prefix += ".";
        }
        if (ns.isBlobSchema()) {
          if (typeof value === "string" || value instanceof Uint8Array) {
            this.writeKey(prefix);
            this.writeValue(
              (this.serdeContext?.base64Encoder ?? utilBase64.toBase64)(value),
            );
          }
        } else if (
          ns.isBooleanSchema() ||
          ns.isNumericSchema() ||
          ns.isStringSchema()
        ) {
          if (value != null) {
            this.writeKey(prefix);
            this.writeValue(String(value));
          } else if (ns.isIdempotencyToken()) {
            this.writeKey(prefix);
            this.writeValue(serde.generateIdempotencyToken());
          }
        } else if (ns.isBigIntegerSchema()) {
          if (value != null) {
            this.writeKey(prefix);
            this.writeValue(String(value));
          }
        } else if (ns.isBigDecimalSchema()) {
          if (value != null) {
            this.writeKey(prefix);
            this.writeValue(
              value instanceof serde.NumericValue
                ? value.string
                : String(value),
            );
          }
        } else if (ns.isTimestampSchema()) {
          if (value instanceof Date) {
            this.writeKey(prefix);
            const format = protocols.determineTimestampFormat(
              ns,
              this.settings,
            );
            switch (format) {
              case 5:
                this.writeValue(value.toISOString().replace(".000Z", "Z"));
                break;
              case 6:
                this.writeValue(smithyClient.dateToUtcString(value));
                break;
              case 7:
                this.writeValue(String(value.getTime() / 1000));
                break;
            }
          }
        } else if (ns.isDocumentSchema()) {
          throw new Error(
            `@aws-sdk/core/protocols - QuerySerializer unsupported document type ${ns.getName(true)}`,
          );
        } else if (ns.isListSchema()) {
          if (Array.isArray(value)) {
            if (value.length === 0) {
              if (this.settings.serializeEmptyLists) {
                this.writeKey(prefix);
                this.writeValue("");
              }
            } else {
              const member = ns.getValueSchema();
              const flat =
                this.settings.flattenLists || ns.getMergedTraits().xmlFlattened;
              let i = 1;
              for (const item of value) {
                if (item == null) {
                  continue;
                }
                const suffix = this.getKey(
                  "member",
                  member.getMergedTraits().xmlName,
                );
                const key = flat ? `${prefix}${i}` : `${prefix}${suffix}.${i}`;
                this.write(member, item, key);
                ++i;
              }
            }
          }
        } else if (ns.isMapSchema()) {
          if (value && typeof value === "object") {
            const keySchema = ns.getKeySchema();
            const memberSchema = ns.getValueSchema();
            const flat = ns.getMergedTraits().xmlFlattened;
            let i = 1;
            for (const [k, v] of Object.entries(value)) {
              if (v == null) {
                continue;
              }
              const keySuffix = this.getKey(
                "key",
                keySchema.getMergedTraits().xmlName,
              );
              const key = flat
                ? `${prefix}${i}.${keySuffix}`
                : `${prefix}entry.${i}.${keySuffix}`;
              const valueSuffix = this.getKey(
                "value",
                memberSchema.getMergedTraits().xmlName,
              );
              const valueKey = flat
                ? `${prefix}${i}.${valueSuffix}`
                : `${prefix}entry.${i}.${valueSuffix}`;
              this.write(keySchema, k, key);
              this.write(memberSchema, v, valueKey);
              ++i;
            }
          }
        } else if (ns.isStructSchema()) {
          if (value && typeof value === "object") {
            for (const [memberName, member] of ns.structIterator()) {
              if (value[memberName] == null && !member.isIdempotencyToken()) {
                continue;
              }
              const suffix = this.getKey(
                memberName,
                member.getMergedTraits().xmlName,
              );
              const key = `${prefix}${suffix}`;
              this.write(member, value[memberName], key);
            }
          }
        } else if (ns.isUnitSchema());
        else {
          throw new Error(
            `@aws-sdk/core/protocols - QuerySerializer unrecognized schema type ${ns.getName(true)}`,
          );
        }
      }
      flush() {
        if (this.buffer === undefined) {
          throw new Error(
            "@aws-sdk/core/protocols - QuerySerializer cannot flush with nothing written to buffer.",
          );
        }
        const str = this.buffer;
        delete this.buffer;
        return str;
      }
      getKey(memberName, xmlName) {
        const key = xmlName ?? memberName;
        if (this.settings.capitalizeKeys) {
          return key[0].toUpperCase() + key.slice(1);
        }
        return key;
      }
      writeKey(key) {
        if (key.endsWith(".")) {
          key = key.slice(0, key.length - 1);
        }
        this.buffer += `&${protocols.extendedEncodeURIComponent(key)}=`;
      }
      writeValue(value) {
        this.buffer += protocols.extendedEncodeURIComponent(value);
      }
    }

    class AwsQueryProtocol extends protocols.RpcProtocol {
      options;
      serializer;
      deserializer;
      mixin = new ProtocolLib();
      constructor(options) {
        super({
          defaultNamespace: options.defaultNamespace,
        });
        this.options = options;
        const settings = {
          timestampFormat: {
            useTrait: true,
            default: 5,
          },
          httpBindings: false,
          xmlNamespace: options.xmlNamespace,
          serviceNamespace: options.defaultNamespace,
          serializeEmptyLists: true,
        };
        this.serializer = new QueryShapeSerializer(settings);
        this.deserializer = new XmlShapeDeserializer(settings);
      }
      getShapeId() {
        return "aws.protocols#awsQuery";
      }
      setSerdeContext(serdeContext) {
        this.serializer.setSerdeContext(serdeContext);
        this.deserializer.setSerdeContext(serdeContext);
      }
      getPayloadCodec() {
        throw new Error("AWSQuery protocol has no payload codec.");
      }
      async serializeRequest(operationSchema, input, context) {
        const request = await super.serializeRequest(
          operationSchema,
          input,
          context,
        );
        if (!request.path.endsWith("/")) {
          request.path += "/";
        }
        Object.assign(request.headers, {
          "content-type": `application/x-www-form-urlencoded`,
        });
        if (schema.deref(operationSchema.input) === "unit" || !request.body) {
          request.body = "";
        }
        const action =
          operationSchema.name.split("#")[1] ?? operationSchema.name;
        request.body =
          `Action=${action}&Version=${this.options.version}` + request.body;
        if (request.body.endsWith("&")) {
          request.body = request.body.slice(-1);
        }
        return request;
      }
      async deserializeResponse(operationSchema, context, response) {
        const deserializer = this.deserializer;
        const ns = schema.NormalizedSchema.of(operationSchema.output);
        const dataObject = {};
        if (response.statusCode >= 300) {
          const bytes = await protocols.collectBody(response.body, context);
          if (bytes.byteLength > 0) {
            Object.assign(dataObject, await deserializer.read(15, bytes));
          }
          await this.handleError(
            operationSchema,
            context,
            response,
            dataObject,
            this.deserializeMetadata(response),
          );
        }
        for (const header in response.headers) {
          const value = response.headers[header];
          delete response.headers[header];
          response.headers[header.toLowerCase()] = value;
        }
        const shortName =
          operationSchema.name.split("#")[1] ?? operationSchema.name;
        const awsQueryResultKey =
          ns.isStructSchema() && this.useNestedResult()
            ? shortName + "Result"
            : undefined;
        const bytes = await protocols.collectBody(response.body, context);
        if (bytes.byteLength > 0) {
          Object.assign(
            dataObject,
            await deserializer.read(ns, bytes, awsQueryResultKey),
          );
        }
        const output = {
          $metadata: this.deserializeMetadata(response),
          ...dataObject,
        };
        return output;
      }
      useNestedResult() {
        return true;
      }
      async handleError(
        operationSchema,
        context,
        response,
        dataObject,
        metadata,
      ) {
        const errorIdentifier =
          this.loadQueryErrorCode(response, dataObject) ?? "Unknown";
        const errorData = this.loadQueryError(dataObject);
        const message = this.loadQueryErrorMessage(dataObject);
        errorData.message = message;
        errorData.Error = {
          Type: errorData.Type,
          Code: errorData.Code,
          Message: message,
        };
        const { errorSchema, errorMetadata } =
          await this.mixin.getErrorSchemaOrThrowBaseException(
            errorIdentifier,
            this.options.defaultNamespace,
            response,
            errorData,
            metadata,
            (registry, errorName) => {
              try {
                return registry.getSchema(errorName);
              } catch (e) {
                return registry.find(
                  (schema$1) =>
                    schema.NormalizedSchema.of(schema$1).getMergedTraits()
                      .awsQueryError?.[0] === errorName,
                );
              }
            },
          );
        const ns = schema.NormalizedSchema.of(errorSchema);
        const ErrorCtor =
          schema.TypeRegistry.for(errorSchema[1]).getErrorCtor(errorSchema) ??
          Error;
        const exception = new ErrorCtor(message);
        const output = {
          Error: errorData.Error,
        };
        for (const [name, member] of ns.structIterator()) {
          const target = member.getMergedTraits().xmlName ?? name;
          const value = errorData[target] ?? dataObject[target];
          output[name] = this.deserializer.readSchema(member, value);
        }
        throw this.mixin.decorateServiceException(
          Object.assign(
            exception,
            errorMetadata,
            {
              $fault: ns.getMergedTraits().error,
              message,
            },
            output,
          ),
          dataObject,
        );
      }
      loadQueryErrorCode(output, data) {
        const code = (
          data.Errors?.[0]?.Error ??
          data.Errors?.Error ??
          data.Error
        )?.Code;
        if (code !== undefined) {
          return code;
        }
        if (output.statusCode == 404) {
          return "NotFound";
        }
      }
      loadQueryError(data) {
        return data.Errors?.[0]?.Error ?? data.Errors?.Error ?? data.Error;
      }
      loadQueryErrorMessage(data) {
        const errorData = this.loadQueryError(data);
        return (
          errorData?.message ??
          errorData?.Message ??
          data.message ??
          data.Message ??
          "Unknown"
        );
      }
      getDefaultContentType() {
        return "application/x-www-form-urlencoded";
      }
    }

    class AwsEc2QueryProtocol extends AwsQueryProtocol {
      options;
      constructor(options) {
        super(options);
        this.options = options;
        const ec2Settings = {
          capitalizeKeys: true,
          flattenLists: true,
          serializeEmptyLists: false,
        };
        Object.assign(this.serializer.settings, ec2Settings);
      }
      useNestedResult() {
        return false;
      }
    }

    const parseXmlBody = (streamBody, context) =>
      collectBodyString(streamBody, context).then((encoded) => {
        if (encoded.length) {
          let parsedObj;
          try {
            parsedObj = xmlBuilder.parseXML(encoded);
          } catch (e) {
            if (e && typeof e === "object") {
              Object.defineProperty(e, "$responseBodyText", {
                value: encoded,
              });
            }
            throw e;
          }
          const textNodeName = "#text";
          const key = Object.keys(parsedObj)[0];
          const parsedObjToReturn = parsedObj[key];
          if (parsedObjToReturn[textNodeName]) {
            parsedObjToReturn[key] = parsedObjToReturn[textNodeName];
            delete parsedObjToReturn[textNodeName];
          }
          return smithyClient.getValueFromTextNode(parsedObjToReturn);
        }
        return {};
      });
    const parseXmlErrorBody = async (errorBody, context) => {
      const value = await parseXmlBody(errorBody, context);
      if (value.Error) {
        value.Error.message = value.Error.message ?? value.Error.Message;
      }
      return value;
    };
    const loadRestXmlErrorCode = (output, data) => {
      if (data?.Error?.Code !== undefined) {
        return data.Error.Code;
      }
      if (data?.Code !== undefined) {
        return data.Code;
      }
      if (output.statusCode == 404) {
        return "NotFound";
      }
    };

    class XmlShapeSerializer extends SerdeContextConfig {
      settings;
      stringBuffer;
      byteBuffer;
      buffer;
      constructor(settings) {
        super();
        this.settings = settings;
      }
      write(schema$1, value) {
        const ns = schema.NormalizedSchema.of(schema$1);
        if (ns.isStringSchema() && typeof value === "string") {
          this.stringBuffer = value;
        } else if (ns.isBlobSchema()) {
          this.byteBuffer =
            "byteLength" in value
              ? value
              : (this.serdeContext?.base64Decoder ?? utilBase64.fromBase64)(
                  value,
                );
        } else {
          this.buffer = this.writeStruct(ns, value, undefined);
          const traits = ns.getMergedTraits();
          if (traits.httpPayload && !traits.xmlName) {
            this.buffer.withName(ns.getName());
          }
        }
      }
      flush() {
        if (this.byteBuffer !== undefined) {
          const bytes = this.byteBuffer;
          delete this.byteBuffer;
          return bytes;
        }
        if (this.stringBuffer !== undefined) {
          const str = this.stringBuffer;
          delete this.stringBuffer;
          return str;
        }
        const buffer = this.buffer;
        if (this.settings.xmlNamespace) {
          if (!buffer?.attributes?.["xmlns"]) {
            buffer.addAttribute("xmlns", this.settings.xmlNamespace);
          }
        }
        delete this.buffer;
        return buffer.toString();
      }
      writeStruct(ns, value, parentXmlns) {
        const traits = ns.getMergedTraits();
        const name =
          ns.isMemberSchema() && !traits.httpPayload
            ? (ns.getMemberTraits().xmlName ?? ns.getMemberName())
            : (traits.xmlName ?? ns.getName());
        if (!name || !ns.isStructSchema()) {
          throw new Error(
            `@aws-sdk/core/protocols - xml serializer, cannot write struct with empty name or non-struct, schema=${ns.getName(true)}.`,
          );
        }
        const structXmlNode = xmlBuilder.XmlNode.of(name);
        const [xmlnsAttr, xmlns] = this.getXmlnsAttribute(ns, parentXmlns);
        for (const [memberName, memberSchema] of ns.structIterator()) {
          const val = value[memberName];
          if (val != null || memberSchema.isIdempotencyToken()) {
            if (memberSchema.getMergedTraits().xmlAttribute) {
              structXmlNode.addAttribute(
                memberSchema.getMergedTraits().xmlName ?? memberName,
                this.writeSimple(memberSchema, val),
              );
              continue;
            }
            if (memberSchema.isListSchema()) {
              this.writeList(memberSchema, val, structXmlNode, xmlns);
            } else if (memberSchema.isMapSchema()) {
              this.writeMap(memberSchema, val, structXmlNode, xmlns);
            } else if (memberSchema.isStructSchema()) {
              structXmlNode.addChildNode(
                this.writeStruct(memberSchema, val, xmlns),
              );
            } else {
              const memberNode = xmlBuilder.XmlNode.of(
                memberSchema.getMergedTraits().xmlName ??
                  memberSchema.getMemberName(),
              );
              this.writeSimpleInto(memberSchema, val, memberNode, xmlns);
              structXmlNode.addChildNode(memberNode);
            }
          }
        }
        if (xmlns) {
          structXmlNode.addAttribute(xmlnsAttr, xmlns);
        }
        return structXmlNode;
      }
      writeList(listMember, array, container, parentXmlns) {
        if (!listMember.isMemberSchema()) {
          throw new Error(
            `@aws-sdk/core/protocols - xml serializer, cannot write non-member list: ${listMember.getName(true)}`,
          );
        }
        const listTraits = listMember.getMergedTraits();
        const listValueSchema = listMember.getValueSchema();
        const listValueTraits = listValueSchema.getMergedTraits();
        const sparse = !!listValueTraits.sparse;
        const flat = !!listTraits.xmlFlattened;
        const [xmlnsAttr, xmlns] = this.getXmlnsAttribute(
          listMember,
          parentXmlns,
        );
        const writeItem = (container, value) => {
          if (listValueSchema.isListSchema()) {
            this.writeList(
              listValueSchema,
              Array.isArray(value) ? value : [value],
              container,
              xmlns,
            );
          } else if (listValueSchema.isMapSchema()) {
            this.writeMap(listValueSchema, value, container, xmlns);
          } else if (listValueSchema.isStructSchema()) {
            const struct = this.writeStruct(listValueSchema, value, xmlns);
            container.addChildNode(
              struct.withName(
                flat
                  ? (listTraits.xmlName ?? listMember.getMemberName())
                  : (listValueTraits.xmlName ?? "member"),
              ),
            );
          } else {
            const listItemNode = xmlBuilder.XmlNode.of(
              flat
                ? (listTraits.xmlName ?? listMember.getMemberName())
                : (listValueTraits.xmlName ?? "member"),
            );
            this.writeSimpleInto(listValueSchema, value, listItemNode, xmlns);
            container.addChildNode(listItemNode);
          }
        };
        if (flat) {
          for (const value of array) {
            if (sparse || value != null) {
              writeItem(container, value);
            }
          }
        } else {
          const listNode = xmlBuilder.XmlNode.of(
            listTraits.xmlName ?? listMember.getMemberName(),
          );
          if (xmlns) {
            listNode.addAttribute(xmlnsAttr, xmlns);
          }
          for (const value of array) {
            if (sparse || value != null) {
              writeItem(listNode, value);
            }
          }
          container.addChildNode(listNode);
        }
      }
      writeMap(mapMember, map, container, parentXmlns, containerIsMap = false) {
        if (!mapMember.isMemberSchema()) {
          throw new Error(
            `@aws-sdk/core/protocols - xml serializer, cannot write non-member map: ${mapMember.getName(true)}`,
          );
        }
        const mapTraits = mapMember.getMergedTraits();
        const mapKeySchema = mapMember.getKeySchema();
        const mapKeyTraits = mapKeySchema.getMergedTraits();
        const keyTag = mapKeyTraits.xmlName ?? "key";
        const mapValueSchema = mapMember.getValueSchema();
        const mapValueTraits = mapValueSchema.getMergedTraits();
        const valueTag = mapValueTraits.xmlName ?? "value";
        const sparse = !!mapValueTraits.sparse;
        const flat = !!mapTraits.xmlFlattened;
        const [xmlnsAttr, xmlns] = this.getXmlnsAttribute(
          mapMember,
          parentXmlns,
        );
        const addKeyValue = (entry, key, val) => {
          const keyNode = xmlBuilder.XmlNode.of(keyTag, key);
          const [keyXmlnsAttr, keyXmlns] = this.getXmlnsAttribute(
            mapKeySchema,
            xmlns,
          );
          if (keyXmlns) {
            keyNode.addAttribute(keyXmlnsAttr, keyXmlns);
          }
          entry.addChildNode(keyNode);
          let valueNode = xmlBuilder.XmlNode.of(valueTag);
          if (mapValueSchema.isListSchema()) {
            this.writeList(mapValueSchema, val, valueNode, xmlns);
          } else if (mapValueSchema.isMapSchema()) {
            this.writeMap(mapValueSchema, val, valueNode, xmlns, true);
          } else if (mapValueSchema.isStructSchema()) {
            valueNode = this.writeStruct(mapValueSchema, val, xmlns);
          } else {
            this.writeSimpleInto(mapValueSchema, val, valueNode, xmlns);
          }
          entry.addChildNode(valueNode);
        };
        if (flat) {
          for (const [key, val] of Object.entries(map)) {
            if (sparse || val != null) {
              const entry = xmlBuilder.XmlNode.of(
                mapTraits.xmlName ?? mapMember.getMemberName(),
              );
              addKeyValue(entry, key, val);
              container.addChildNode(entry);
            }
          }
        } else {
          let mapNode;
          if (!containerIsMap) {
            mapNode = xmlBuilder.XmlNode.of(
              mapTraits.xmlName ?? mapMember.getMemberName(),
            );
            if (xmlns) {
              mapNode.addAttribute(xmlnsAttr, xmlns);
            }
            container.addChildNode(mapNode);
          }
          for (const [key, val] of Object.entries(map)) {
            if (sparse || val != null) {
              const entry = xmlBuilder.XmlNode.of("entry");
              addKeyValue(entry, key, val);
              (containerIsMap ? container : mapNode).addChildNode(entry);
            }
          }
        }
      }
      writeSimple(_schema, value) {
        if (null === value) {
          throw new Error(
            "@aws-sdk/core/protocols - (XML serializer) cannot write null value.",
          );
        }
        const ns = schema.NormalizedSchema.of(_schema);
        let nodeContents = null;
        if (value && typeof value === "object") {
          if (ns.isBlobSchema()) {
            nodeContents = (
              this.serdeContext?.base64Encoder ?? utilBase64.toBase64
            )(value);
          } else if (ns.isTimestampSchema() && value instanceof Date) {
            const format = protocols.determineTimestampFormat(
              ns,
              this.settings,
            );
            switch (format) {
              case 5:
                nodeContents = value.toISOString().replace(".000Z", "Z");
                break;
              case 6:
                nodeContents = smithyClient.dateToUtcString(value);
                break;
              case 7:
                nodeContents = String(value.getTime() / 1000);
                break;
              default:
                console.warn(
                  "Missing timestamp format, using http date",
                  value,
                );
                nodeContents = smithyClient.dateToUtcString(value);
                break;
            }
          } else if (ns.isBigDecimalSchema() && value) {
            if (value instanceof serde.NumericValue) {
              return value.string;
            }
            return String(value);
          } else if (ns.isMapSchema() || ns.isListSchema()) {
            throw new Error(
              "@aws-sdk/core/protocols - xml serializer, cannot call _write() on List/Map schema, call writeList or writeMap() instead.",
            );
          } else {
            throw new Error(
              `@aws-sdk/core/protocols - xml serializer, unhandled schema type for object value and schema: ${ns.getName(true)}`,
            );
          }
        }
        if (
          ns.isBooleanSchema() ||
          ns.isNumericSchema() ||
          ns.isBigIntegerSchema() ||
          ns.isBigDecimalSchema()
        ) {
          nodeContents = String(value);
        }
        if (ns.isStringSchema()) {
          if (value === undefined && ns.isIdempotencyToken()) {
            nodeContents = serde.generateIdempotencyToken();
          } else {
            nodeContents = String(value);
          }
        }
        if (nodeContents === null) {
          throw new Error(
            `Unhandled schema-value pair ${ns.getName(true)}=${value}`,
          );
        }
        return nodeContents;
      }
      writeSimpleInto(_schema, value, into, parentXmlns) {
        const nodeContents = this.writeSimple(_schema, value);
        const ns = schema.NormalizedSchema.of(_schema);
        const content = new xmlBuilder.XmlText(nodeContents);
        const [xmlnsAttr, xmlns] = this.getXmlnsAttribute(ns, parentXmlns);
        if (xmlns) {
          into.addAttribute(xmlnsAttr, xmlns);
        }
        into.addChildNode(content);
      }
      getXmlnsAttribute(ns, parentXmlns) {
        const traits = ns.getMergedTraits();
        const [prefix, xmlns] = traits.xmlNamespace ?? [];
        if (xmlns && xmlns !== parentXmlns) {
          return [prefix ? `xmlns:${prefix}` : "xmlns", xmlns];
        }
        return [void 0, void 0];
      }
    }

    class XmlCodec extends SerdeContextConfig {
      settings;
      constructor(settings) {
        super();
        this.settings = settings;
      }
      createSerializer() {
        const serializer = new XmlShapeSerializer(this.settings);
        serializer.setSerdeContext(this.serdeContext);
        return serializer;
      }
      createDeserializer() {
        const deserializer = new XmlShapeDeserializer(this.settings);
        deserializer.setSerdeContext(this.serdeContext);
        return deserializer;
      }
    }

    class AwsRestXmlProtocol extends protocols.HttpBindingProtocol {
      codec;
      serializer;
      deserializer;
      mixin = new ProtocolLib();
      constructor(options) {
        super(options);
        const settings = {
          timestampFormat: {
            useTrait: true,
            default: 5,
          },
          httpBindings: true,
          xmlNamespace: options.xmlNamespace,
          serviceNamespace: options.defaultNamespace,
        };
        this.codec = new XmlCodec(settings);
        this.serializer = new protocols.HttpInterceptingShapeSerializer(
          this.codec.createSerializer(),
          settings,
        );
        this.deserializer = new protocols.HttpInterceptingShapeDeserializer(
          this.codec.createDeserializer(),
          settings,
        );
      }
      getPayloadCodec() {
        return this.codec;
      }
      getShapeId() {
        return "aws.protocols#restXml";
      }
      async serializeRequest(operationSchema, input, context) {
        const request = await super.serializeRequest(
          operationSchema,
          input,
          context,
        );
        const inputSchema = schema.NormalizedSchema.of(operationSchema.input);
        if (!request.headers["content-type"]) {
          const contentType = this.mixin.resolveRestContentType(
            this.getDefaultContentType(),
            inputSchema,
          );
          if (contentType) {
            request.headers["content-type"] = contentType;
          }
        }
        if (request.headers["content-type"] === this.getDefaultContentType()) {
          if (typeof request.body === "string") {
            request.body =
              '<?xml version="1.0" encoding="UTF-8"?>' + request.body;
          }
        }
        return request;
      }
      async deserializeResponse(operationSchema, context, response) {
        return super.deserializeResponse(operationSchema, context, response);
      }
      async handleError(
        operationSchema,
        context,
        response,
        dataObject,
        metadata,
      ) {
        const errorIdentifier =
          loadRestXmlErrorCode(response, dataObject) ?? "Unknown";
        const { errorSchema, errorMetadata } =
          await this.mixin.getErrorSchemaOrThrowBaseException(
            errorIdentifier,
            this.options.defaultNamespace,
            response,
            dataObject,
            metadata,
          );
        const ns = schema.NormalizedSchema.of(errorSchema);
        const message =
          dataObject.Error?.message ??
          dataObject.Error?.Message ??
          dataObject.message ??
          dataObject.Message ??
          "Unknown";
        const ErrorCtor =
          schema.TypeRegistry.for(errorSchema[1]).getErrorCtor(errorSchema) ??
          Error;
        const exception = new ErrorCtor(message);
        await this.deserializeHttpMessage(
          errorSchema,
          context,
          response,
          dataObject,
        );
        const output = {};
        for (const [name, member] of ns.structIterator()) {
          const target = member.getMergedTraits().xmlName ?? name;
          const value = dataObject.Error?.[target] ?? dataObject[target];
          output[name] = this.codec
            .createDeserializer()
            .readSchema(member, value);
        }
        throw this.mixin.decorateServiceException(
          Object.assign(
            exception,
            errorMetadata,
            {
              $fault: ns.getMergedTraits().error,
              message,
            },
            output,
          ),
          dataObject,
        );
      }
      getDefaultContentType() {
        return "application/xml";
      }
    }

    exports.AwsEc2QueryProtocol = AwsEc2QueryProtocol;
    exports.AwsJson1_0Protocol = AwsJson1_0Protocol;
    exports.AwsJson1_1Protocol = AwsJson1_1Protocol;
    exports.AwsJsonRpcProtocol = AwsJsonRpcProtocol;
    exports.AwsQueryProtocol = AwsQueryProtocol;
    exports.AwsRestJsonProtocol = AwsRestJsonProtocol;
    exports.AwsRestXmlProtocol = AwsRestXmlProtocol;
    exports.AwsSmithyRpcV2CborProtocol = AwsSmithyRpcV2CborProtocol;
    exports.JsonCodec = JsonCodec;
    exports.JsonShapeDeserializer = JsonShapeDeserializer;
    exports.JsonShapeSerializer = JsonShapeSerializer;
    exports.XmlCodec = XmlCodec;
    exports.XmlShapeDeserializer = XmlShapeDeserializer;
    exports.XmlShapeSerializer = XmlShapeSerializer;
    exports._toBool = _toBool;
    exports._toNum = _toNum;
    exports._toStr = _toStr;
    exports.awsExpectUnion = awsExpectUnion;
    exports.loadRestJsonErrorCode = loadRestJsonErrorCode;
    exports.loadRestXmlErrorCode = loadRestXmlErrorCode;
    exports.parseJsonBody = parseJsonBody;
    exports.parseJsonErrorBody = parseJsonErrorBody;
    exports.parseXmlBody = parseXmlBody;
    exports.parseXmlErrorBody = parseXmlErrorBody;

    /***/
  },

  /***/ 6352: /***/ (__unused_webpack_module, exports, __webpack_require__) => {
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

  /***/ 4316: /***/ (__unused_webpack_module, exports) => {
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

  /***/ 7682: /***/ (__unused_webpack_module, exports, __webpack_require__) => {
    var recursionDetectionMiddleware = __webpack_require__(6143);

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

  /***/ 6143: /***/ (__unused_webpack_module, exports, __webpack_require__) => {
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

  /***/ 9033: /***/ (__unused_webpack_module, exports, __webpack_require__) => {
    var core = __webpack_require__(402);
    var utilEndpoints = __webpack_require__(8178);
    var protocolHttp = __webpack_require__(2356);
    var core$1 = __webpack_require__(9722);

    const DEFAULT_UA_APP_ID = undefined;
    function isValidUserAgentAppId(appId) {
      if (appId === undefined) {
        return true;
      }
      return typeof appId === "string" && appId.length <= 50;
    }
    function resolveUserAgentConfig(input) {
      const normalizedAppIdProvider = core.normalizeProvider(
        input.userAgentAppId ?? DEFAULT_UA_APP_ID,
      );
      const { customUserAgent } = input;
      return Object.assign(input, {
        customUserAgent:
          typeof customUserAgent === "string"
            ? [[customUserAgent]]
            : customUserAgent,
        userAgentAppId: async () => {
          const appId = await normalizedAppIdProvider();
          if (!isValidUserAgentAppId(appId)) {
            const logger =
              input.logger?.constructor?.name === "NoOpLogger" || !input.logger
                ? console
                : input.logger;
            if (typeof appId !== "string") {
              logger?.warn("userAgentAppId must be a string or undefined.");
            } else if (appId.length > 50) {
              logger?.warn(
                "The provided userAgentAppId exceeds the maximum length of 50 characters.",
              );
            }
          }
          return appId;
        },
      });
    }

    const ACCOUNT_ID_ENDPOINT_REGEX = /\d{12}\.ddb/;
    async function checkFeatures(context, config, args) {
      const request = args.request;
      if (request?.headers?.["smithy-protocol"] === "rpc-v2-cbor") {
        core$1.setFeature(context, "PROTOCOL_RPC_V2_CBOR", "M");
      }
      if (typeof config.retryStrategy === "function") {
        const retryStrategy = await config.retryStrategy();
        if (typeof retryStrategy.acquireInitialRetryToken === "function") {
          if (retryStrategy.constructor?.name?.includes("Adaptive")) {
            core$1.setFeature(context, "RETRY_MODE_ADAPTIVE", "F");
          } else {
            core$1.setFeature(context, "RETRY_MODE_STANDARD", "E");
          }
        } else {
          core$1.setFeature(context, "RETRY_MODE_LEGACY", "D");
        }
      }
      if (typeof config.accountIdEndpointMode === "function") {
        const endpointV2 = context.endpointV2;
        if (
          String(endpointV2?.url?.hostname).match(ACCOUNT_ID_ENDPOINT_REGEX)
        ) {
          core$1.setFeature(context, "ACCOUNT_ID_ENDPOINT", "O");
        }
        switch (await config.accountIdEndpointMode?.()) {
          case "disabled":
            core$1.setFeature(context, "ACCOUNT_ID_MODE_DISABLED", "Q");
            break;
          case "preferred":
            core$1.setFeature(context, "ACCOUNT_ID_MODE_PREFERRED", "P");
            break;
          case "required":
            core$1.setFeature(context, "ACCOUNT_ID_MODE_REQUIRED", "R");
            break;
        }
      }
      const identity =
        context.__smithy_context?.selectedHttpAuthScheme?.identity;
      if (identity?.$source) {
        const credentials = identity;
        if (credentials.accountId) {
          core$1.setFeature(context, "RESOLVED_ACCOUNT_ID", "T");
        }
        for (const [key, value] of Object.entries(credentials.$source ?? {})) {
          core$1.setFeature(context, key, value);
        }
      }
    }

    const USER_AGENT = "user-agent";
    const X_AMZ_USER_AGENT = "x-amz-user-agent";
    const SPACE = " ";
    const UA_NAME_SEPARATOR = "/";
    const UA_NAME_ESCAPE_REGEX = /[^!$%&'*+\-.^_`|~\w]/g;
    const UA_VALUE_ESCAPE_REGEX = /[^!$%&'*+\-.^_`|~\w#]/g;
    const UA_ESCAPE_CHAR = "-";

    const BYTE_LIMIT = 1024;
    function encodeFeatures(features) {
      let buffer = "";
      for (const key in features) {
        const val = features[key];
        if (buffer.length + val.length + 1 <= BYTE_LIMIT) {
          if (buffer.length) {
            buffer += "," + val;
          } else {
            buffer += val;
          }
          continue;
        }
        break;
      }
      return buffer;
    }

    const userAgentMiddleware =
      (options) => (next, context) => async (args) => {
        const { request } = args;
        if (!protocolHttp.HttpRequest.isInstance(request)) {
          return next(args);
        }
        const { headers } = request;
        const userAgent = context?.userAgent?.map(escapeUserAgent) || [];
        const defaultUserAgent = (await options.defaultUserAgentProvider()).map(
          escapeUserAgent,
        );
        await checkFeatures(context, options, args);
        const awsContext = context;
        defaultUserAgent.push(
          `m/${encodeFeatures(Object.assign({}, context.__smithy_context?.features, awsContext.__aws_sdk_context?.features))}`,
        );
        const customUserAgent =
          options?.customUserAgent?.map(escapeUserAgent) || [];
        const appId = await options.userAgentAppId();
        if (appId) {
          defaultUserAgent.push(escapeUserAgent([`app`, `${appId}`]));
        }
        const prefix = utilEndpoints.getUserAgentPrefix();
        const sdkUserAgentValue = (prefix ? [prefix] : [])
          .concat([...defaultUserAgent, ...userAgent, ...customUserAgent])
          .join(SPACE);
        const normalUAValue = [
          ...defaultUserAgent.filter((section) =>
            section.startsWith("aws-sdk-"),
          ),
          ...customUserAgent,
        ].join(SPACE);
        if (options.runtime !== "browser") {
          if (normalUAValue) {
            headers[X_AMZ_USER_AGENT] = headers[X_AMZ_USER_AGENT]
              ? `${headers[USER_AGENT]} ${normalUAValue}`
              : normalUAValue;
          }
          headers[USER_AGENT] = sdkUserAgentValue;
        } else {
          headers[X_AMZ_USER_AGENT] = sdkUserAgentValue;
        }
        return next({
          ...args,
          request,
        });
      };
    const escapeUserAgent = (userAgentPair) => {
      const name = userAgentPair[0]
        .split(UA_NAME_SEPARATOR)
        .map((part) => part.replace(UA_NAME_ESCAPE_REGEX, UA_ESCAPE_CHAR))
        .join(UA_NAME_SEPARATOR);
      const version = userAgentPair[1]?.replace(
        UA_VALUE_ESCAPE_REGEX,
        UA_ESCAPE_CHAR,
      );
      const prefixSeparatorIndex = name.indexOf(UA_NAME_SEPARATOR);
      const prefix = name.substring(0, prefixSeparatorIndex);
      let uaName = name.substring(prefixSeparatorIndex + 1);
      if (prefix === "api") {
        uaName = uaName.toLowerCase();
      }
      return [prefix, uaName, version]
        .filter((item) => item && item.length > 0)
        .reduce((acc, item, index) => {
          switch (index) {
            case 0:
              return item;
            case 1:
              return `${acc}/${item}`;
            default:
              return `${acc}#${item}`;
          }
        }, "");
    };
    const getUserAgentMiddlewareOptions = {
      name: "getUserAgentMiddleware",
      step: "build",
      priority: "low",
      tags: ["SET_USER_AGENT", "USER_AGENT"],
      override: true,
    };
    const getUserAgentPlugin = (config) => ({
      applyToStack: (clientStack) => {
        clientStack.add(
          userAgentMiddleware(config),
          getUserAgentMiddlewareOptions,
        );
      },
    });

    exports.DEFAULT_UA_APP_ID = DEFAULT_UA_APP_ID;
    exports.getUserAgentMiddlewareOptions = getUserAgentMiddlewareOptions;
    exports.getUserAgentPlugin = getUserAgentPlugin;
    exports.resolveUserAgentConfig = resolveUserAgentConfig;
    exports.userAgentMiddleware = userAgentMiddleware;

    /***/
  },

  /***/ 8127: /***/ (__unused_webpack_module, exports, __webpack_require__) => {
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.resolveHttpAuthSchemeConfig =
      exports.defaultSigninHttpAuthSchemeProvider =
      exports.defaultSigninHttpAuthSchemeParametersProvider =
        void 0;
    const core_1 = __webpack_require__(9722);
    const util_middleware_1 = __webpack_require__(6324);
    const defaultSigninHttpAuthSchemeParametersProvider = async (
      config,
      context,
      input,
    ) => {
      return {
        operation: (0, util_middleware_1.getSmithyContext)(context).operation,
        region:
          (await (0, util_middleware_1.normalizeProvider)(config.region)()) ||
          (() => {
            throw new Error(
              "expected `region` to be configured for `aws.auth#sigv4`",
            );
          })(),
      };
    };
    exports.defaultSigninHttpAuthSchemeParametersProvider =
      defaultSigninHttpAuthSchemeParametersProvider;
    function createAwsAuthSigv4HttpAuthOption(authParameters) {
      return {
        schemeId: "aws.auth#sigv4",
        signingProperties: {
          name: "signin",
          region: authParameters.region,
        },
        propertiesExtractor: (config, context) => ({
          signingProperties: {
            config,
            context,
          },
        }),
      };
    }
    function createSmithyApiNoAuthHttpAuthOption(authParameters) {
      return {
        schemeId: "smithy.api#noAuth",
      };
    }
    const defaultSigninHttpAuthSchemeProvider = (authParameters) => {
      const options = [];
      switch (authParameters.operation) {
        case "CreateOAuth2Token": {
          options.push(createSmithyApiNoAuthHttpAuthOption(authParameters));
          break;
        }
        default: {
          options.push(createAwsAuthSigv4HttpAuthOption(authParameters));
        }
      }
      return options;
    };
    exports.defaultSigninHttpAuthSchemeProvider =
      defaultSigninHttpAuthSchemeProvider;
    const resolveHttpAuthSchemeConfig = (config) => {
      const config_0 = (0, core_1.resolveAwsSdkSigV4Config)(config);
      return Object.assign(config_0, {
        authSchemePreference: (0, util_middleware_1.normalizeProvider)(
          config.authSchemePreference ?? [],
        ),
      });
    };
    exports.resolveHttpAuthSchemeConfig = resolveHttpAuthSchemeConfig;

    /***/
  },

  /***/ 3449: /***/ (__unused_webpack_module, exports, __webpack_require__) => {
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.defaultEndpointResolver = void 0;
    const util_endpoints_1 = __webpack_require__(8178);
    const util_endpoints_2 = __webpack_require__(9674);
    const ruleset_1 = __webpack_require__(594);
    const cache = new util_endpoints_2.EndpointCache({
      size: 50,
      params: ["Endpoint", "Region", "UseDualStack", "UseFIPS"],
    });
    const defaultEndpointResolver = (endpointParams, context = {}) => {
      return cache.get(endpointParams, () =>
        (0, util_endpoints_2.resolveEndpoint)(ruleset_1.ruleSet, {
          endpointParams: endpointParams,
          logger: context.logger,
        }),
      );
    };
    exports.defaultEndpointResolver = defaultEndpointResolver;
    util_endpoints_2.customEndpointFunctions.aws =
      util_endpoints_1.awsEndpointFunctions;

    /***/
  },

  /***/ 594: /***/ (__unused_webpack_module, exports) => {
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.ruleSet = void 0;
    const u = "required",
      v = "fn",
      w = "argv",
      x = "ref";
    const a = true,
      b = "isSet",
      c = "booleanEquals",
      d = "error",
      e = "endpoint",
      f = "tree",
      g = "PartitionResult",
      h = "stringEquals",
      i = { [u]: true, default: false, type: "boolean" },
      j = { [u]: false, type: "string" },
      k = { [x]: "Endpoint" },
      l = { [v]: c, [w]: [{ [x]: "UseFIPS" }, true] },
      m = { [v]: c, [w]: [{ [x]: "UseDualStack" }, true] },
      n = {},
      o = { [v]: "getAttr", [w]: [{ [x]: g }, "name"] },
      p = { [v]: c, [w]: [{ [x]: "UseFIPS" }, false] },
      q = { [v]: c, [w]: [{ [x]: "UseDualStack" }, false] },
      r = { [v]: "getAttr", [w]: [{ [x]: g }, "supportsFIPS"] },
      s = {
        [v]: c,
        [w]: [true, { [v]: "getAttr", [w]: [{ [x]: g }, "supportsDualStack"] }],
      },
      t = [{ [x]: "Region" }];
    const _data = {
      version: "1.0",
      parameters: { UseDualStack: i, UseFIPS: i, Endpoint: j, Region: j },
      rules: [
        {
          conditions: [{ [v]: b, [w]: [k] }],
          rules: [
            {
              conditions: [l],
              error:
                "Invalid Configuration: FIPS and custom endpoint are not supported",
              type: d,
            },
            {
              rules: [
                {
                  conditions: [m],
                  error:
                    "Invalid Configuration: Dualstack and custom endpoint are not supported",
                  type: d,
                },
                { endpoint: { url: k, properties: n, headers: n }, type: e },
              ],
              type: f,
            },
          ],
          type: f,
        },
        {
          rules: [
            {
              conditions: [{ [v]: b, [w]: t }],
              rules: [
                {
                  conditions: [{ [v]: "aws.partition", [w]: t, assign: g }],
                  rules: [
                    {
                      conditions: [{ [v]: h, [w]: [o, "aws"] }, p, q],
                      endpoint: {
                        url: "https://{Region}.signin.aws.amazon.com",
                        properties: n,
                        headers: n,
                      },
                      type: e,
                    },
                    {
                      conditions: [{ [v]: h, [w]: [o, "aws-cn"] }, p, q],
                      endpoint: {
                        url: "https://{Region}.signin.amazonaws.cn",
                        properties: n,
                        headers: n,
                      },
                      type: e,
                    },
                    {
                      conditions: [{ [v]: h, [w]: [o, "aws-us-gov"] }, p, q],
                      endpoint: {
                        url: "https://{Region}.signin.amazonaws-us-gov.com",
                        properties: n,
                        headers: n,
                      },
                      type: e,
                    },
                    {
                      conditions: [l, m],
                      rules: [
                        {
                          conditions: [{ [v]: c, [w]: [a, r] }, s],
                          rules: [
                            {
                              endpoint: {
                                url: "https://signin-fips.{Region}.{PartitionResult#dualStackDnsSuffix}",
                                properties: n,
                                headers: n,
                              },
                              type: e,
                            },
                          ],
                          type: f,
                        },
                        {
                          error:
                            "FIPS and DualStack are enabled, but this partition does not support one or both",
                          type: d,
                        },
                      ],
                      type: f,
                    },
                    {
                      conditions: [l, q],
                      rules: [
                        {
                          conditions: [{ [v]: c, [w]: [r, a] }],
                          rules: [
                            {
                              endpoint: {
                                url: "https://signin-fips.{Region}.{PartitionResult#dnsSuffix}",
                                properties: n,
                                headers: n,
                              },
                              type: e,
                            },
                          ],
                          type: f,
                        },
                        {
                          error:
                            "FIPS is enabled but this partition does not support FIPS",
                          type: d,
                        },
                      ],
                      type: f,
                    },
                    {
                      conditions: [p, m],
                      rules: [
                        {
                          conditions: [s],
                          rules: [
                            {
                              endpoint: {
                                url: "https://signin.{Region}.{PartitionResult#dualStackDnsSuffix}",
                                properties: n,
                                headers: n,
                              },
                              type: e,
                            },
                          ],
                          type: f,
                        },
                        {
                          error:
                            "DualStack is enabled but this partition does not support DualStack",
                          type: d,
                        },
                      ],
                      type: f,
                    },
                    {
                      endpoint: {
                        url: "https://signin.{Region}.{PartitionResult#dnsSuffix}",
                        properties: n,
                        headers: n,
                      },
                      type: e,
                    },
                  ],
                  type: f,
                },
              ],
              type: f,
            },
            { error: "Invalid Configuration: Missing Region", type: d },
          ],
          type: f,
        },
      ],
    };
    exports.ruleSet = _data;

    /***/
  },

  /***/ 6652: /***/ (__unused_webpack_module, exports, __webpack_require__) => {
    var __webpack_unused_export__;

    var middlewareHostHeader = __webpack_require__(6352);
    var middlewareLogger = __webpack_require__(4316);
    var middlewareRecursionDetection = __webpack_require__(7682);
    var middlewareUserAgent = __webpack_require__(9033);
    var configResolver = __webpack_require__(9316);
    var core = __webpack_require__(402);
    var schema = __webpack_require__(6890);
    var middlewareContentLength = __webpack_require__(7212);
    var middlewareEndpoint = __webpack_require__(99);
    var middlewareRetry = __webpack_require__(9618);
    var smithyClient = __webpack_require__(1411);
    var httpAuthSchemeProvider = __webpack_require__(8127);
    var runtimeConfig = __webpack_require__(4270);
    var regionConfigResolver = __webpack_require__(4677);
    var protocolHttp = __webpack_require__(2356);

    const resolveClientEndpointParameters = (options) => {
      return Object.assign(options, {
        useDualstackEndpoint: options.useDualstackEndpoint ?? false,
        useFipsEndpoint: options.useFipsEndpoint ?? false,
        defaultSigningName: "signin",
      });
    };
    const commonParams = {
      UseFIPS: { type: "builtInParams", name: "useFipsEndpoint" },
      Endpoint: { type: "builtInParams", name: "endpoint" },
      Region: { type: "builtInParams", name: "region" },
      UseDualStack: { type: "builtInParams", name: "useDualstackEndpoint" },
    };

    const getHttpAuthExtensionConfiguration = (runtimeConfig) => {
      const _httpAuthSchemes = runtimeConfig.httpAuthSchemes;
      let _httpAuthSchemeProvider = runtimeConfig.httpAuthSchemeProvider;
      let _credentials = runtimeConfig.credentials;
      return {
        setHttpAuthScheme(httpAuthScheme) {
          const index = _httpAuthSchemes.findIndex(
            (scheme) => scheme.schemeId === httpAuthScheme.schemeId,
          );
          if (index === -1) {
            _httpAuthSchemes.push(httpAuthScheme);
          } else {
            _httpAuthSchemes.splice(index, 1, httpAuthScheme);
          }
        },
        httpAuthSchemes() {
          return _httpAuthSchemes;
        },
        setHttpAuthSchemeProvider(httpAuthSchemeProvider) {
          _httpAuthSchemeProvider = httpAuthSchemeProvider;
        },
        httpAuthSchemeProvider() {
          return _httpAuthSchemeProvider;
        },
        setCredentials(credentials) {
          _credentials = credentials;
        },
        credentials() {
          return _credentials;
        },
      };
    };
    const resolveHttpAuthRuntimeConfig = (config) => {
      return {
        httpAuthSchemes: config.httpAuthSchemes(),
        httpAuthSchemeProvider: config.httpAuthSchemeProvider(),
        credentials: config.credentials(),
      };
    };

    const resolveRuntimeExtensions = (runtimeConfig, extensions) => {
      const extensionConfiguration = Object.assign(
        regionConfigResolver.getAwsRegionExtensionConfiguration(runtimeConfig),
        smithyClient.getDefaultExtensionConfiguration(runtimeConfig),
        protocolHttp.getHttpHandlerExtensionConfiguration(runtimeConfig),
        getHttpAuthExtensionConfiguration(runtimeConfig),
      );
      extensions.forEach((extension) =>
        extension.configure(extensionConfiguration),
      );
      return Object.assign(
        runtimeConfig,
        regionConfigResolver.resolveAwsRegionExtensionConfiguration(
          extensionConfiguration,
        ),
        smithyClient.resolveDefaultRuntimeConfig(extensionConfiguration),
        protocolHttp.resolveHttpHandlerRuntimeConfig(extensionConfiguration),
        resolveHttpAuthRuntimeConfig(extensionConfiguration),
      );
    };

    class SigninClient extends smithyClient.Client {
      config;
      constructor(...[configuration]) {
        const _config_0 = runtimeConfig.getRuntimeConfig(configuration || {});
        super(_config_0);
        this.initConfig = _config_0;
        const _config_1 = resolveClientEndpointParameters(_config_0);
        const _config_2 = middlewareUserAgent.resolveUserAgentConfig(_config_1);
        const _config_3 = middlewareRetry.resolveRetryConfig(_config_2);
        const _config_4 = configResolver.resolveRegionConfig(_config_3);
        const _config_5 =
          middlewareHostHeader.resolveHostHeaderConfig(_config_4);
        const _config_6 = middlewareEndpoint.resolveEndpointConfig(_config_5);
        const _config_7 =
          httpAuthSchemeProvider.resolveHttpAuthSchemeConfig(_config_6);
        const _config_8 = resolveRuntimeExtensions(
          _config_7,
          configuration?.extensions || [],
        );
        this.config = _config_8;
        this.middlewareStack.use(schema.getSchemaSerdePlugin(this.config));
        this.middlewareStack.use(
          middlewareUserAgent.getUserAgentPlugin(this.config),
        );
        this.middlewareStack.use(middlewareRetry.getRetryPlugin(this.config));
        this.middlewareStack.use(
          middlewareContentLength.getContentLengthPlugin(this.config),
        );
        this.middlewareStack.use(
          middlewareHostHeader.getHostHeaderPlugin(this.config),
        );
        this.middlewareStack.use(middlewareLogger.getLoggerPlugin(this.config));
        this.middlewareStack.use(
          middlewareRecursionDetection.getRecursionDetectionPlugin(this.config),
        );
        this.middlewareStack.use(
          core.getHttpAuthSchemeEndpointRuleSetPlugin(this.config, {
            httpAuthSchemeParametersProvider:
              httpAuthSchemeProvider.defaultSigninHttpAuthSchemeParametersProvider,
            identityProviderConfigProvider: async (config) =>
              new core.DefaultIdentityProviderConfig({
                "aws.auth#sigv4": config.credentials,
              }),
          }),
        );
        this.middlewareStack.use(core.getHttpSigningPlugin(this.config));
      }
      destroy() {
        super.destroy();
      }
    }

    let SigninServiceException$1 = class SigninServiceException
      extends smithyClient.ServiceException
    {
      constructor(options) {
        super(options);
        Object.setPrototypeOf(this, SigninServiceException.prototype);
      }
    };

    let AccessDeniedException$1 = class AccessDeniedException extends SigninServiceException$1 {
      name = "AccessDeniedException";
      $fault = "client";
      error;
      constructor(opts) {
        super({
          name: "AccessDeniedException",
          $fault: "client",
          ...opts,
        });
        Object.setPrototypeOf(this, AccessDeniedException.prototype);
        this.error = opts.error;
      }
    };
    let InternalServerException$1 = class InternalServerException extends SigninServiceException$1 {
      name = "InternalServerException";
      $fault = "server";
      error;
      constructor(opts) {
        super({
          name: "InternalServerException",
          $fault: "server",
          ...opts,
        });
        Object.setPrototypeOf(this, InternalServerException.prototype);
        this.error = opts.error;
      }
    };
    let TooManyRequestsError$1 = class TooManyRequestsError extends SigninServiceException$1 {
      name = "TooManyRequestsError";
      $fault = "client";
      error;
      constructor(opts) {
        super({
          name: "TooManyRequestsError",
          $fault: "client",
          ...opts,
        });
        Object.setPrototypeOf(this, TooManyRequestsError.prototype);
        this.error = opts.error;
      }
    };
    let ValidationException$1 = class ValidationException extends SigninServiceException$1 {
      name = "ValidationException";
      $fault = "client";
      error;
      constructor(opts) {
        super({
          name: "ValidationException",
          $fault: "client",
          ...opts,
        });
        Object.setPrototypeOf(this, ValidationException.prototype);
        this.error = opts.error;
      }
    };

    const _ADE = "AccessDeniedException";
    const _AT = "AccessToken";
    const _COAT = "CreateOAuth2Token";
    const _COATR = "CreateOAuth2TokenRequest";
    const _COATRB = "CreateOAuth2TokenRequestBody";
    const _COATRBr = "CreateOAuth2TokenResponseBody";
    const _COATRr = "CreateOAuth2TokenResponse";
    const _ISE = "InternalServerException";
    const _RT = "RefreshToken";
    const _TMRE = "TooManyRequestsError";
    const _VE = "ValidationException";
    const _aKI = "accessKeyId";
    const _aT = "accessToken";
    const _c = "client";
    const _cI = "clientId";
    const _cV = "codeVerifier";
    const _co = "code";
    const _e = "error";
    const _eI = "expiresIn";
    const _gT = "grantType";
    const _h = "http";
    const _hE = "httpError";
    const _iT = "idToken";
    const _jN = "jsonName";
    const _m = "message";
    const _rT = "refreshToken";
    const _rU = "redirectUri";
    const _s = "server";
    const _sAK = "secretAccessKey";
    const _sT = "sessionToken";
    const _sm = "smithy.ts.sdk.synthetic.com.amazonaws.signin";
    const _tI = "tokenInput";
    const _tO = "tokenOutput";
    const _tT = "tokenType";
    const n0 = "com.amazonaws.signin";
    var RefreshToken = [0, n0, _RT, 8, 0];
    var AccessDeniedException = [
      -3,
      n0,
      _ADE,
      {
        [_e]: _c,
      },
      [_e, _m],
      [0, 0],
    ];
    schema.TypeRegistry.for(n0).registerError(
      AccessDeniedException,
      AccessDeniedException$1,
    );
    var AccessToken = [
      3,
      n0,
      _AT,
      8,
      [_aKI, _sAK, _sT],
      [
        [
          0,
          {
            [_jN]: _aKI,
          },
        ],
        [
          0,
          {
            [_jN]: _sAK,
          },
        ],
        [
          0,
          {
            [_jN]: _sT,
          },
        ],
      ],
    ];
    var CreateOAuth2TokenRequest = [
      3,
      n0,
      _COATR,
      0,
      [_tI],
      [[() => CreateOAuth2TokenRequestBody, 16]],
    ];
    var CreateOAuth2TokenRequestBody = [
      3,
      n0,
      _COATRB,
      0,
      [_cI, _gT, _co, _rU, _cV, _rT],
      [
        [
          0,
          {
            [_jN]: _cI,
          },
        ],
        [
          0,
          {
            [_jN]: _gT,
          },
        ],
        0,
        [
          0,
          {
            [_jN]: _rU,
          },
        ],
        [
          0,
          {
            [_jN]: _cV,
          },
        ],
        [
          () => RefreshToken,
          {
            [_jN]: _rT,
          },
        ],
      ],
    ];
    var CreateOAuth2TokenResponse = [
      3,
      n0,
      _COATRr,
      0,
      [_tO],
      [[() => CreateOAuth2TokenResponseBody, 16]],
    ];
    var CreateOAuth2TokenResponseBody = [
      3,
      n0,
      _COATRBr,
      0,
      [_aT, _tT, _eI, _rT, _iT],
      [
        [
          () => AccessToken,
          {
            [_jN]: _aT,
          },
        ],
        [
          0,
          {
            [_jN]: _tT,
          },
        ],
        [
          1,
          {
            [_jN]: _eI,
          },
        ],
        [
          () => RefreshToken,
          {
            [_jN]: _rT,
          },
        ],
        [
          0,
          {
            [_jN]: _iT,
          },
        ],
      ],
    ];
    var InternalServerException = [
      -3,
      n0,
      _ISE,
      {
        [_e]: _s,
        [_hE]: 500,
      },
      [_e, _m],
      [0, 0],
    ];
    schema.TypeRegistry.for(n0).registerError(
      InternalServerException,
      InternalServerException$1,
    );
    var TooManyRequestsError = [
      -3,
      n0,
      _TMRE,
      {
        [_e]: _c,
        [_hE]: 429,
      },
      [_e, _m],
      [0, 0],
    ];
    schema.TypeRegistry.for(n0).registerError(
      TooManyRequestsError,
      TooManyRequestsError$1,
    );
    var ValidationException = [
      -3,
      n0,
      _VE,
      {
        [_e]: _c,
        [_hE]: 400,
      },
      [_e, _m],
      [0, 0],
    ];
    schema.TypeRegistry.for(n0).registerError(
      ValidationException,
      ValidationException$1,
    );
    var SigninServiceException = [-3, _sm, "SigninServiceException", 0, [], []];
    schema.TypeRegistry.for(_sm).registerError(
      SigninServiceException,
      SigninServiceException$1,
    );
    var CreateOAuth2Token = [
      9,
      n0,
      _COAT,
      {
        [_h]: ["POST", "/v1/token", 200],
      },
      () => CreateOAuth2TokenRequest,
      () => CreateOAuth2TokenResponse,
    ];

    class CreateOAuth2TokenCommand extends smithyClient.Command.classBuilder()
      .ep(commonParams)
      .m(function (Command, cs, config, o) {
        return [
          middlewareEndpoint.getEndpointPlugin(
            config,
            Command.getEndpointParameterInstructions(),
          ),
        ];
      })
      .s("Signin", "CreateOAuth2Token", {})
      .n("SigninClient", "CreateOAuth2TokenCommand")
      .sc(CreateOAuth2Token)
      .build() {}

    const commands = {
      CreateOAuth2TokenCommand,
    };
    class Signin extends SigninClient {}
    smithyClient.createAggregatedClient(commands, Signin);

    const OAuth2ErrorCode = {
      AUTHCODE_EXPIRED: "AUTHCODE_EXPIRED",
      INSUFFICIENT_PERMISSIONS: "INSUFFICIENT_PERMISSIONS",
      INVALID_REQUEST: "INVALID_REQUEST",
      SERVER_ERROR: "server_error",
      TOKEN_EXPIRED: "TOKEN_EXPIRED",
      USER_CREDENTIALS_CHANGED: "USER_CREDENTIALS_CHANGED",
    };

    __webpack_unused_export__ = {
      enumerable: true,
      get: function () {
        return smithyClient.Command;
      },
    };
    __webpack_unused_export__ = {
      enumerable: true,
      get: function () {
        return smithyClient.Client;
      },
    };
    __webpack_unused_export__ = AccessDeniedException$1;
    exports.CreateOAuth2TokenCommand = CreateOAuth2TokenCommand;
    __webpack_unused_export__ = InternalServerException$1;
    __webpack_unused_export__ = OAuth2ErrorCode;
    __webpack_unused_export__ = Signin;
    exports.SigninClient = SigninClient;
    __webpack_unused_export__ = SigninServiceException$1;
    __webpack_unused_export__ = TooManyRequestsError$1;
    __webpack_unused_export__ = ValidationException$1;

    /***/
  },

  /***/ 4270: /***/ (__unused_webpack_module, exports, __webpack_require__) => {
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.getRuntimeConfig = void 0;
    const tslib_1 = __webpack_require__(1860);
    const package_json_1 = tslib_1.__importDefault(__webpack_require__(5197));
    const core_1 = __webpack_require__(9722);
    const util_user_agent_node_1 = __webpack_require__(8974);
    const config_resolver_1 = __webpack_require__(9316);
    const hash_node_1 = __webpack_require__(5092);
    const middleware_retry_1 = __webpack_require__(9618);
    const node_config_provider_1 = __webpack_require__(5704);
    const node_http_handler_1 = __webpack_require__(1279);
    const util_body_length_node_1 = __webpack_require__(3638);
    const util_retry_1 = __webpack_require__(5518);
    const runtimeConfig_shared_1 = __webpack_require__(9111);
    const smithy_client_1 = __webpack_require__(1411);
    const util_defaults_mode_node_1 = __webpack_require__(5435);
    const smithy_client_2 = __webpack_require__(1411);
    const getRuntimeConfig = (config) => {
      (0, smithy_client_2.emitWarningIfUnsupportedVersion)(process.version);
      const defaultsMode = (0,
      util_defaults_mode_node_1.resolveDefaultsModeConfig)(config);
      const defaultConfigProvider = () =>
        defaultsMode().then(smithy_client_1.loadConfigsForDefaultMode);
      const clientSharedValues = (0, runtimeConfig_shared_1.getRuntimeConfig)(
        config,
      );
      (0, core_1.emitWarningIfUnsupportedVersion)(process.version);
      const loaderConfig = {
        profile: config?.profile,
        logger: clientSharedValues.logger,
      };
      return {
        ...clientSharedValues,
        ...config,
        runtime: "node",
        defaultsMode,
        authSchemePreference:
          config?.authSchemePreference ??
          (0, node_config_provider_1.loadConfig)(
            core_1.NODE_AUTH_SCHEME_PREFERENCE_OPTIONS,
            loaderConfig,
          ),
        bodyLengthChecker:
          config?.bodyLengthChecker ??
          util_body_length_node_1.calculateBodyLength,
        defaultUserAgentProvider:
          config?.defaultUserAgentProvider ??
          (0, util_user_agent_node_1.createDefaultUserAgentProvider)({
            serviceId: clientSharedValues.serviceId,
            clientVersion: package_json_1.default.version,
          }),
        maxAttempts:
          config?.maxAttempts ??
          (0, node_config_provider_1.loadConfig)(
            middleware_retry_1.NODE_MAX_ATTEMPT_CONFIG_OPTIONS,
            config,
          ),
        region:
          config?.region ??
          (0, node_config_provider_1.loadConfig)(
            config_resolver_1.NODE_REGION_CONFIG_OPTIONS,
            {
              ...config_resolver_1.NODE_REGION_CONFIG_FILE_OPTIONS,
              ...loaderConfig,
            },
          ),
        requestHandler: node_http_handler_1.NodeHttpHandler.create(
          config?.requestHandler ?? defaultConfigProvider,
        ),
        retryMode:
          config?.retryMode ??
          (0, node_config_provider_1.loadConfig)(
            {
              ...middleware_retry_1.NODE_RETRY_MODE_CONFIG_OPTIONS,
              default: async () =>
                (await defaultConfigProvider()).retryMode ||
                util_retry_1.DEFAULT_RETRY_MODE,
            },
            config,
          ),
        sha256: config?.sha256 ?? hash_node_1.Hash.bind(null, "sha256"),
        streamCollector:
          config?.streamCollector ?? node_http_handler_1.streamCollector,
        useDualstackEndpoint:
          config?.useDualstackEndpoint ??
          (0, node_config_provider_1.loadConfig)(
            config_resolver_1.NODE_USE_DUALSTACK_ENDPOINT_CONFIG_OPTIONS,
            loaderConfig,
          ),
        useFipsEndpoint:
          config?.useFipsEndpoint ??
          (0, node_config_provider_1.loadConfig)(
            config_resolver_1.NODE_USE_FIPS_ENDPOINT_CONFIG_OPTIONS,
            loaderConfig,
          ),
        userAgentAppId:
          config?.userAgentAppId ??
          (0, node_config_provider_1.loadConfig)(
            util_user_agent_node_1.NODE_APP_ID_CONFIG_OPTIONS,
            loaderConfig,
          ),
      };
    };
    exports.getRuntimeConfig = getRuntimeConfig;

    /***/
  },

  /***/ 9111: /***/ (__unused_webpack_module, exports, __webpack_require__) => {
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.getRuntimeConfig = void 0;
    const core_1 = __webpack_require__(9722);
    const protocols_1 = __webpack_require__(5222);
    const core_2 = __webpack_require__(402);
    const smithy_client_1 = __webpack_require__(1411);
    const url_parser_1 = __webpack_require__(4494);
    const util_base64_1 = __webpack_require__(8385);
    const util_utf8_1 = __webpack_require__(1577);
    const httpAuthSchemeProvider_1 = __webpack_require__(8127);
    const endpointResolver_1 = __webpack_require__(3449);
    const getRuntimeConfig = (config) => {
      return {
        apiVersion: "2023-01-01",
        base64Decoder: config?.base64Decoder ?? util_base64_1.fromBase64,
        base64Encoder: config?.base64Encoder ?? util_base64_1.toBase64,
        disableHostPrefix: config?.disableHostPrefix ?? false,
        endpointProvider:
          config?.endpointProvider ??
          endpointResolver_1.defaultEndpointResolver,
        extensions: config?.extensions ?? [],
        httpAuthSchemeProvider:
          config?.httpAuthSchemeProvider ??
          httpAuthSchemeProvider_1.defaultSigninHttpAuthSchemeProvider,
        httpAuthSchemes: config?.httpAuthSchemes ?? [
          {
            schemeId: "aws.auth#sigv4",
            identityProvider: (ipc) =>
              ipc.getIdentityProvider("aws.auth#sigv4"),
            signer: new core_1.AwsSdkSigV4Signer(),
          },
          {
            schemeId: "smithy.api#noAuth",
            identityProvider: (ipc) =>
              ipc.getIdentityProvider("smithy.api#noAuth") ||
              (async () => ({})),
            signer: new core_2.NoAuthSigner(),
          },
        ],
        logger: config?.logger ?? new smithy_client_1.NoOpLogger(),
        protocol:
          config?.protocol ??
          new protocols_1.AwsRestJsonProtocol({
            defaultNamespace: "com.amazonaws.signin",
          }),
        serviceId: config?.serviceId ?? "Signin",
        urlParser: config?.urlParser ?? url_parser_1.parseUrl,
        utf8Decoder: config?.utf8Decoder ?? util_utf8_1.fromUtf8,
        utf8Encoder: config?.utf8Encoder ?? util_utf8_1.toUtf8,
      };
    };
    exports.getRuntimeConfig = getRuntimeConfig;

    /***/
  },

  /***/ 4677: /***/ (__unused_webpack_module, exports, __webpack_require__) => {
    var configResolver = __webpack_require__(9316);
    var stsRegionDefaultResolver = __webpack_require__(5005);

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

  /***/ 5005: /***/ (__unused_webpack_module, exports, __webpack_require__) => {
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

  /***/ 8178: /***/ (__unused_webpack_module, exports, __webpack_require__) => {
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

  /***/ 8974: /***/ (__unused_webpack_module, exports, __webpack_require__) => {
    var os = __webpack_require__(857);
    var process = __webpack_require__(932);
    var middlewareUserAgent = __webpack_require__(9033);

    const crtAvailability = {
      isCrtAvailable: false,
    };

    const isCrtAvailable = () => {
      if (crtAvailability.isCrtAvailable) {
        return ["md/crt-avail"];
      }
      return null;
    };

    const createDefaultUserAgentProvider = ({ serviceId, clientVersion }) => {
      return async (config) => {
        const sections = [
          ["aws-sdk-js", clientVersion],
          ["ua", "2.1"],
          [`os/${os.platform()}`, os.release()],
          ["lang/js"],
          ["md/nodejs", `${process.versions.node}`],
        ];
        const crtAvailable = isCrtAvailable();
        if (crtAvailable) {
          sections.push(crtAvailable);
        }
        if (serviceId) {
          sections.push([`api/${serviceId}`, clientVersion]);
        }
        if (process.env.AWS_EXECUTION_ENV) {
          sections.push([`exec-env/${process.env.AWS_EXECUTION_ENV}`]);
        }
        const appId = await config?.userAgentAppId?.();
        const resolvedUserAgent = appId
          ? [...sections, [`app/${appId}`]]
          : [...sections];
        return resolvedUserAgent;
      };
    };
    const defaultUserAgent = createDefaultUserAgentProvider;

    const UA_APP_ID_ENV_NAME = "AWS_SDK_UA_APP_ID";
    const UA_APP_ID_INI_NAME = "sdk_ua_app_id";
    const UA_APP_ID_INI_NAME_DEPRECATED = "sdk-ua-app-id";
    const NODE_APP_ID_CONFIG_OPTIONS = {
      environmentVariableSelector: (env) => env[UA_APP_ID_ENV_NAME],
      configFileSelector: (profile) =>
        profile[UA_APP_ID_INI_NAME] ?? profile[UA_APP_ID_INI_NAME_DEPRECATED],
      default: middlewareUserAgent.DEFAULT_UA_APP_ID,
    };

    exports.NODE_APP_ID_CONFIG_OPTIONS = NODE_APP_ID_CONFIG_OPTIONS;
    exports.UA_APP_ID_ENV_NAME = UA_APP_ID_ENV_NAME;
    exports.UA_APP_ID_INI_NAME = UA_APP_ID_INI_NAME;
    exports.createDefaultUserAgentProvider = createDefaultUserAgentProvider;
    exports.crtAvailability = crtAvailability;
    exports.defaultUserAgent = defaultUserAgent;

    /***/
  },

  /***/ 7660: /***/ (__unused_webpack_module, exports, __webpack_require__) => {
    var xmlParser = __webpack_require__(5397);

    function escapeAttribute(value) {
      return value
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
    }

    function escapeElement(value) {
      return value
        .replace(/&/g, "&amp;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&apos;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/\r/g, "&#x0D;")
        .replace(/\n/g, "&#x0A;")
        .replace(/\u0085/g, "&#x85;")
        .replace(/\u2028/, "&#x2028;");
    }

    class XmlText {
      value;
      constructor(value) {
        this.value = value;
      }
      toString() {
        return escapeElement("" + this.value);
      }
    }

    class XmlNode {
      name;
      children;
      attributes = {};
      static of(name, childText, withName) {
        const node = new XmlNode(name);
        if (childText !== undefined) {
          node.addChildNode(new XmlText(childText));
        }
        if (withName !== undefined) {
          node.withName(withName);
        }
        return node;
      }
      constructor(name, children = []) {
        this.name = name;
        this.children = children;
      }
      withName(name) {
        this.name = name;
        return this;
      }
      addAttribute(name, value) {
        this.attributes[name] = value;
        return this;
      }
      addChildNode(child) {
        this.children.push(child);
        return this;
      }
      removeAttribute(name) {
        delete this.attributes[name];
        return this;
      }
      n(name) {
        this.name = name;
        return this;
      }
      c(child) {
        this.children.push(child);
        return this;
      }
      a(name, value) {
        if (value != null) {
          this.attributes[name] = value;
        }
        return this;
      }
      cc(input, field, withName = field) {
        if (input[field] != null) {
          const node = XmlNode.of(field, input[field]).withName(withName);
          this.c(node);
        }
      }
      l(input, listName, memberName, valueProvider) {
        if (input[listName] != null) {
          const nodes = valueProvider();
          nodes.map((node) => {
            node.withName(memberName);
            this.c(node);
          });
        }
      }
      lc(input, listName, memberName, valueProvider) {
        if (input[listName] != null) {
          const nodes = valueProvider();
          const containerNode = new XmlNode(memberName);
          nodes.map((node) => {
            containerNode.c(node);
          });
          this.c(containerNode);
        }
      }
      toString() {
        const hasChildren = Boolean(this.children.length);
        let xmlText = `<${this.name}`;
        const attributes = this.attributes;
        for (const attributeName of Object.keys(attributes)) {
          const attribute = attributes[attributeName];
          if (attribute != null) {
            xmlText += ` ${attributeName}="${escapeAttribute("" + attribute)}"`;
          }
        }
        return (xmlText += !hasChildren
          ? "/>"
          : `>${this.children.map((c) => c.toString()).join("")}</${this.name}>`);
      }
    }

    Object.defineProperty(exports, "parseXML", {
      enumerable: true,
      get: function () {
        return xmlParser.parseXML;
      },
    });
    exports.XmlNode = XmlNode;
    exports.XmlText = XmlText;

    /***/
  },

  /***/ 5397: /***/ (__unused_webpack_module, exports, __webpack_require__) => {
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.parseXML = parseXML;
    const fast_xml_parser_1 = __webpack_require__(591);
    const parser = new fast_xml_parser_1.XMLParser({
      attributeNamePrefix: "",
      htmlEntities: true,
      ignoreAttributes: false,
      ignoreDeclaration: true,
      parseTagValue: false,
      trimValues: false,
      tagValueProcessor: (_, val) =>
        val.trim() === "" && val.includes("\n") ? "" : undefined,
    });
    parser.addEntity("#xD", "\r");
    parser.addEntity("#10", "\n");
    function parseXML(xmlString) {
      return parser.parse(xmlString, true);
    }

    /***/
  },

  /***/ 5197: /***/ (module) => {
    module.exports = /*#__PURE__*/ JSON.parse(
      '{"name":"@aws-sdk/nested-clients","version":"3.936.0","description":"Nested clients for AWS SDK packages.","main":"./dist-cjs/index.js","module":"./dist-es/index.js","types":"./dist-types/index.d.ts","scripts":{"build":"yarn lint && concurrently \'yarn:build:cjs\' \'yarn:build:es\' \'yarn:build:types\'","build:cjs":"node ../../scripts/compilation/inline nested-clients","build:es":"tsc -p tsconfig.es.json","build:include:deps":"lerna run --scope $npm_package_name --include-dependencies build","build:types":"tsc -p tsconfig.types.json","build:types:downlevel":"downlevel-dts dist-types dist-types/ts3.4","clean":"rimraf ./dist-* && rimraf *.tsbuildinfo","lint":"node ../../scripts/validation/submodules-linter.js --pkg nested-clients","test":"yarn g:vitest run","test:watch":"yarn g:vitest watch"},"engines":{"node":">=18.0.0"},"sideEffects":false,"author":{"name":"AWS SDK for JavaScript Team","url":"https://aws.amazon.com/javascript/"},"license":"Apache-2.0","dependencies":{"@aws-crypto/sha256-browser":"5.2.0","@aws-crypto/sha256-js":"5.2.0","@aws-sdk/core":"3.936.0","@aws-sdk/middleware-host-header":"3.936.0","@aws-sdk/middleware-logger":"3.936.0","@aws-sdk/middleware-recursion-detection":"3.936.0","@aws-sdk/middleware-user-agent":"3.936.0","@aws-sdk/region-config-resolver":"3.936.0","@aws-sdk/types":"3.936.0","@aws-sdk/util-endpoints":"3.936.0","@aws-sdk/util-user-agent-browser":"3.936.0","@aws-sdk/util-user-agent-node":"3.936.0","@smithy/config-resolver":"^4.4.3","@smithy/core":"^3.18.5","@smithy/fetch-http-handler":"^5.3.6","@smithy/hash-node":"^4.2.5","@smithy/invalid-dependency":"^4.2.5","@smithy/middleware-content-length":"^4.2.5","@smithy/middleware-endpoint":"^4.3.12","@smithy/middleware-retry":"^4.4.12","@smithy/middleware-serde":"^4.2.6","@smithy/middleware-stack":"^4.2.5","@smithy/node-config-provider":"^4.3.5","@smithy/node-http-handler":"^4.4.5","@smithy/protocol-http":"^5.3.5","@smithy/smithy-client":"^4.9.8","@smithy/types":"^4.9.0","@smithy/url-parser":"^4.2.5","@smithy/util-base64":"^4.3.0","@smithy/util-body-length-browser":"^4.2.0","@smithy/util-body-length-node":"^4.2.1","@smithy/util-defaults-mode-browser":"^4.3.11","@smithy/util-defaults-mode-node":"^4.2.14","@smithy/util-endpoints":"^3.2.5","@smithy/util-middleware":"^4.2.5","@smithy/util-retry":"^4.2.5","@smithy/util-utf8":"^4.2.0","tslib":"^2.6.2"},"devDependencies":{"concurrently":"7.0.0","downlevel-dts":"0.10.1","rimraf":"3.0.2","typescript":"~5.8.3"},"typesVersions":{"<4.0":{"dist-types/*":["dist-types/ts3.4/*"]}},"files":["./signin.d.ts","./signin.js","./sso-oidc.d.ts","./sso-oidc.js","./sts.d.ts","./sts.js","dist-*/**"],"browser":{"./dist-es/submodules/signin/runtimeConfig":"./dist-es/submodules/signin/runtimeConfig.browser","./dist-es/submodules/sso-oidc/runtimeConfig":"./dist-es/submodules/sso-oidc/runtimeConfig.browser","./dist-es/submodules/sts/runtimeConfig":"./dist-es/submodules/sts/runtimeConfig.browser"},"react-native":{},"homepage":"https://github.com/aws/aws-sdk-js-v3/tree/main/packages/nested-clients","repository":{"type":"git","url":"https://github.com/aws/aws-sdk-js-v3.git","directory":"packages/nested-clients"},"exports":{"./package.json":"./package.json","./sso-oidc":{"types":"./dist-types/submodules/sso-oidc/index.d.ts","module":"./dist-es/submodules/sso-oidc/index.js","node":"./dist-cjs/submodules/sso-oidc/index.js","import":"./dist-es/submodules/sso-oidc/index.js","require":"./dist-cjs/submodules/sso-oidc/index.js"},"./sts":{"types":"./dist-types/submodules/sts/index.d.ts","module":"./dist-es/submodules/sts/index.js","node":"./dist-cjs/submodules/sts/index.js","import":"./dist-es/submodules/sts/index.js","require":"./dist-cjs/submodules/sts/index.js"},"./signin":{"types":"./dist-types/submodules/signin/index.d.ts","module":"./dist-es/submodules/signin/index.js","node":"./dist-cjs/submodules/signin/index.js","import":"./dist-es/submodules/signin/index.js","require":"./dist-cjs/submodules/signin/index.js"}}}',
    );

    /***/
  },
};
//# sourceMappingURL=652.index.js.map
