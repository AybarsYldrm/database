'use strict';

// @fitfak/database -- public entry point.
//
// Three layers, each usable on its own:
//
//   engine        the embedded encrypted store (src/index.js). No network, no gRPC.
//   grpc          server and client for reaching that store over mTLS.
//   provisioning  how a service with no certificate gets one, so it can use the above.
//
// A process that only needs the embedded engine pays for nothing else -- the gRPC and
// provisioning modules are loaded on first use, so `require('@fitfak/database')` in a CLI tool
// does not drag in an HTTP/2 server.

const engine = require('./src');

// The transport and enrolment surfaces are behind getters rather than plain requires: they
// pull in @fitfak/grpc, and a caller using only the embedded database should not have to have
// it installed.
const lazy = {
  get grpcServer() { return require('./src/grpc/server'); },
  get grpcClient() { return require('./src/grpc/client'); },
  get grpcSchemas() { return require('./src/grpc/schemas'); },
  get grpcIdentity() { return require('./src/grpc/identity'); },
  get recordCodec() { return require('./src/grpc/record-codec'); },
  get enrollmentService() { return require('./src/provisioning/enrollment-service'); },
  get enrollmentClient() { return require('./src/provisioning/enrollment-client'); },
  get attestor() { return require('./src/provisioning/attestor'); },
  get caBackend() { return require('./src/provisioning/ca-backend'); },
  get csrProvider() { return require('./src/provisioning/csr-provider'); },
};

module.exports = {
  ...engine,

  // ---- server -------------------------------------------------------------------------------
  get DatabaseServer() { return lazy.grpcServer.DatabaseServer; },
  get createDatabaseServer() { return lazy.grpcServer.createDatabaseServer; },

  // ---- client -------------------------------------------------------------------------------
  get connectDatabase() { return lazy.grpcClient.connectDatabase; },
  get RemoteDatabase() { return lazy.grpcClient.RemoteDatabase; },
  get RemoteCollection() { return lazy.grpcClient.RemoteCollection; },
  get WatchedCollection() { return lazy.grpcClient.WatchedCollection; },

  // ---- wire ---------------------------------------------------------------------------------
  get DATABASE_SCHEMAS() { return lazy.grpcSchemas.DATABASE_SCHEMAS; },
  get WATCH_EVENTS() { return lazy.grpcSchemas.WATCH_EVENTS; },
  get recordCodec() { return lazy.recordCodec; },

  // ---- identity -----------------------------------------------------------------------------
  get createPrincipalResolver() { return lazy.grpcIdentity.createPrincipalResolver; },
  get ROLE_PERMISSIONS() { return lazy.grpcIdentity.ROLE_PERMISSIONS; },

  // ---- provisioning: bootstrap TLS -> enrol -> mTLS ------------------------------------------
  get createEnrollmentService() { return lazy.enrollmentService.createEnrollmentService; },
  get ENROLMENT_SCHEMAS() { return lazy.enrollmentService.ENROLMENT_SCHEMAS; },
  get enroll() { return lazy.enrollmentClient.enroll; },
  get reenroll() { return lazy.enrollmentClient.reenroll; },
  get ManagedIdentity() { return lazy.enrollmentClient.ManagedIdentity; },
  get TrustError() { return lazy.enrollmentClient.TrustError; },

  // ---- provisioning: who may enrol as what ---------------------------------------------------
  get createSharedSecretAttestor() { return lazy.attestor.createSharedSecretAttestor; },
  get createTokenAttestor() { return lazy.attestor.createTokenAttestor; },
  get createRenewalAttestor() { return lazy.attestor.createRenewalAttestor; },
  get createCompositeAttestor() { return lazy.attestor.createCompositeAttestor; },
  get generateEnrolmentSecret() { return lazy.attestor.generateEnrolmentSecret; },
  get computeEnrolmentProof() { return lazy.attestor.computeEnrolmentProof; },
  get EnrolmentDenied() { return lazy.attestor.EnrolmentDenied; },

  // ---- provisioning: where certificates come from --------------------------------------------
  // This package is a Registration Authority, never a CA: it decides who may hold which
  // identity, and delegates every signature to one of these backends.
  get createFitfakSslCaBackend() { return lazy.caBackend.createFitfakSslCaBackend; },
  get createAcmeCaBackend() { return lazy.caBackend.createAcmeCaBackend; },
  get createCustomCaBackend() { return lazy.caBackend.createCustomCaBackend; },
  get createFitfakSslCsrProvider() { return lazy.csrProvider.createFitfakSslCsrProvider; },
  get createCustomCsrProvider() { return lazy.csrProvider.createCustomCsrProvider; },
};
