const sodium = require("sodium-native");

const isCanonicalBase64 = (base64String) =>
  Buffer.from(base64String, "base64").toString("base64") === base64String;

const getValidationError = (message, state, hmacKey) => {
  // state
  if (state == null) {
    state = { id: null, sequence: 0 };
  }

  // hmacKey
  if (hmacKey != null) {
    if (typeof hmacKey !== "string") {
      return new Error("HMAC key must be a string");
    }
    if (Buffer.from(hmacKey, "base64").length !== sodium.crypto_auth_KEYBYTES) {
      return new Error(
        `HMAC key must decode to a value with ${sodium.crypto_auth_KEYBYTES} bytes`
      );
    }
  }

  // message
  if (typeof message !== "object") {
    return new Error("Message must be an object");
  }
  if (message == null) {
    return new Error("Message must not be null");
  }
  if (Buffer.byteLength(JSON.stringify(message, null, 2), "latin1") > 8192) {
    return new Error(
      "Message must decode a value with fewer than 8192 bytes (latin1)"
    );
  }
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
  const keys = Object.keys(message);
  const hasValidOrder = validOrders.some((order) => {
    return JSON.stringify(order) === JSON.stringify(keys);
  });
  if (hasValidOrder === false) {
    return new Error("Message must have a valid order");
  }

  // message.author
  if (typeof message.author !== "string") {
    return new Error("Message author must be a string");
  }
  const authorSuffix = ".ed25519";
  if (message.author.endsWith(authorSuffix) === false) {
    return new Error(`Message author must end with '${authorSuffix}'`);
  }
  // message.sequence
  if (typeof message.sequence !== "number") {
    return new Error("Message sequence must be a number");
  }
  if (message.sequence !== state.sequence + 1) {
    return new Error(
      "Message sequence must be the previous sequence number plus one"
    );
  }

  // message.hash
  if (message.hash !== "sha256") {
    return new Error("Message hash must be 'sha256'");
  }

  // message.timestamp
  if (typeof message.timestamp !== "number") {
    return new Error("Message timestamp must be a number");
  }

  // message.content
  if (typeof message.content === "string") {
    if (message.content.includes(".box") === false) {
      return new Error("Message content string must contain '.box'");
    }
    const boxCharacters = message.content.split(".box")[0];
    if (isCanonicalBase64(boxCharacters) === false) {
      return new Error("Message content string base64 must be canonical");
    }
  } else if (typeof message.content === "object") {
    if (message.content === null) {
      return new Error("Message content must not be null");
    }
    if (Array.isArray(message.content)) {
      return new Error("Message content must not be an array");
    }

    // mesage.content.type
    if (typeof message.content.type !== "string") {
      return new Error("Message content type must be a string");
    }
    if (message.content.type.length > 52) {
      return new Error(
        "Message content type length must not be greater than 52"
      );
    }
    if (message.content.type.length < 3) {
      return new Error("Message content type length must not be less than 3");
    }
  } else {
    return new Error("Message content must be a string or an object");
  }

  // message.signature
  const signatureSuffix = `.sig.ed25519`;
  if (message.signature.endsWith(signatureSuffix) === false) {
    return new Error(`Message signature must end with '${signatureSuffix}'`);
  }
  const signatureCharacters = message.signature.slice(
    0,
    -signatureSuffix.length
  );
  if (isCanonicalBase64(signatureCharacters) === false) {
    return new Error("Signature base64 must be canonical");
  }
  const signatureBytes = Buffer.from(signatureCharacters, "base64");
  if (signatureBytes.length !== sodium.crypto_sign_BYTES) {
    return new Error(
      `Signature must decode to a value with ${sodium.crypto_sign_BYTES} bytes`
    );
  }
  const unsignedMessageObject = Object.fromEntries(
    Object.entries(message).filter(([key]) => key !== "signature")
  );
  const unsignedMessageBytes = Buffer.from(
    JSON.stringify(unsignedMessageObject, null, 2)
  );
  const publicKey = Buffer.from(
    message.author.slice(0, -authorSuffix.length),
    "base64"
  );
  if (publicKey.length !== sodium.crypto_sign_PUBLICKEYBYTES) {
    return new Error(
      `Author must decode to a value with ${sodium.crypto_sign_PUBLICKEYBYTES} bytes`
    );
  }
  if (hmacKey == null) {
    const isValidSignature = sodium.crypto_sign_verify_detached(
      signatureBytes,
      unsignedMessageBytes,
      publicKey
    );

    if (isValidSignature !== true) {
      return new Error(
        "Signature value must verify the unsigned message bytes"
      );
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
      return new Error(
        "Signature value must verify the unsigned message bytes"
      );
    }
  }

  // If we've made it this far, there are no errors.
  return null;
};

const isValid = (message, state, hmacKey) => {
  const error = getValidationError(message, state, hmacKey);
  if (error === null) {
    return true;
  } else {
    return false;
  }
};

module.exports = {
  isValid,
  getValidationError,
};
