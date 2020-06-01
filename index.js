const sodium = require("sodium-native");

const isCanonicalBase64 = (base64String) =>
  Buffer.from(base64String, "base64").toString("base64") === base64String;

module.exports = (value, state = { id: null, sequence: 0 }, hmacKey) => {
  // hmacKey
  if (hmacKey !== null) {
    if (typeof hmacKey !== "string") {
      return false;
    }
    if (Buffer.from(hmacKey, "base64").length !== sodium.crypto_auth_KEYBYTES) {
      return false;
    }
  }

  // .
  if (typeof value !== "object") {
    return false;
  }
  if (value == null) {
    return false;
  }
  if (Buffer.byteLength(JSON.stringify(value, null, 2), "latin1") > 8192) {
    return false;
  }

  // . (key ordering
  const validOrders = [
    [
      "previous",
      "author",
      "sequence",
      "timestamp",
      "hash",
      "content",
      "signature",
    ],
    [
      "previous",
      "sequence",
      "author",
      "timestamp",
      "hash",
      "content",
      "signature",
    ],
  ];
  const keys = Object.keys(value);
  const hasValidOrder = validOrders.some((order) => {
    return JSON.stringify(order) === JSON.stringify(keys);
  });
  if (hasValidOrder === false) {
    return false;
  }

  // .author
  if (typeof value.author !== "string") {
    return false;
  }
  if (value.author.endsWith("ed25519") === false) {
    return false;
  }

  // .sequence
  if (typeof value.sequence !== "number") {
    return false;
  }
  if (value.sequence !== state.sequence + 1) {
    return false;
  }

  // .hash
  if (value.hash !== "sha256") {
    return false;
  }
  // .timestamp
  if (typeof value.timestamp !== "number") {
    return false;
  }
  // .content
  if (typeof value.content === "string") {
    // -1 is magic number for "not found"
    if (value.content.indexOf(".box") === -1) {
      return false;
    }
    const boxCharacters = value.content.split(".box")[0];
    if (isCanonicalBase64(boxCharacters) === false) {
      return false;
    }
  } else if (typeof value.content === "object") {
    if (value.content === null) {
      return false;
    }
    if (Array.isArray(value.content)) {
      return false;
    }
    // .content.type
    if (typeof value.content.type !== "string") {
      return false;
    }
    if (value.content.type.length > 52) {
      return false;
    }
    if (value.content.type.length < 3) {
      return false;
    }
  } else {
    return false;
  }

  // .signature
  const signatureSuffix = ".sig.ed25519";
  if (value.signature.endsWith(signatureSuffix) === false) {
    return false;
  }
  const signatureCharacters = value.signature.slice(
    0,
    value.signature.length - signatureSuffix.length
  );
  if (isCanonicalBase64(signatureCharacters) === false) {
    return false;
  }
  const signatureBytes = Buffer.from(signatureCharacters, "base64");
  if (signatureBytes.length !== sodium.crypto_sign_BYTES) {
    return false;
  }

  const unsignedMessageObject = Object.fromEntries(
    Object.entries(value).filter(([key]) => key !== "signature")
  );

  const unsignedMessageBytes = Buffer.from(
    JSON.stringify(unsignedMessageObject, null, 2)
  );
  const publicKey = Buffer.from(value.author.split(".ed25519")[0], "base64");

  if (publicKey.length !== sodium.crypto_sign_PUBLICKEYBYTES) {
    return false;
  }

  if (hmacKey == null) {
    const isValidSignature = sodium.crypto_sign_verify_detached(
      signatureBytes,
      unsignedMessageBytes,
      publicKey
    );

    if (isValidSignature !== true) {
      return false;
    }
  } else {
    const out = Buffer.alloc(sodium.crypto_auth_BYTES);
    sodium.crypto_auth(
      out,
      unsignedMessageBytes,
      Buffer.from(hmacKey, "base64")
    );

    const isValidSignature = sodium.crypto_sign_verify_detached(
      signatureBytes,
      out,
      publicKey
    );

    if (isValidSignature !== true) {
      return false;
    }
  }

  return true;
};
