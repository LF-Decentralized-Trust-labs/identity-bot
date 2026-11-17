/// The Employee Authorization credential schema's identifier.
///
/// Asserted in `identity-agent-core/schemas/credential-schema-vectors.json`
/// (and checked against the schema file by `credential_schemas_test.go`); this
/// is the one Dart copy, so an app does not carry its own.
const String kEmployeeAuthorizationSchemaSaid =
    'EDVkEBpme7o5heShoep_GqoIGDD9U8PisaFKqwrp9O51';

/// The placeholder identifier credentials issued before the real schema
/// existed still carry. A holder must keep recognising it.
const String kEmployeeAuthorizationRetiredPlaceholderSaid =
    'EEmployeeAuth__placeholder__v1';

/// Every identifier an Employee Authorization credential may carry: the
/// current one and the retired placeholder.
const Set<String> kEmployeeAuthorizationSchemaSaids = {
  kEmployeeAuthorizationSchemaSaid,
  kEmployeeAuthorizationRetiredPlaceholderSaid,
};
