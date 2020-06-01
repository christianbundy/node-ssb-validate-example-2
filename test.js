const tap = require("tap");
const fs = require("fs");
const { isValid, getValidationError } = require("./");

const isValidWord = {
  true: "valid",
  false: "invalid",
};

const messages = JSON.parse(fs.readFileSync("fixtures/messages.json", "utf8"));
messages.forEach(({ state, message, hmacKey, valid, error }) => {
  const result = isValid(message, state, hmacKey);

  tap.equal(result, valid, `Message should be ${isValidWord[valid]}`, {
    message,
    state,
    hmacKey,
  });

  const validationError = getValidationError(message, state, hmacKey);

  if (validationError !== null) {
    tap.equal(validationError.message, error);
    if (validationError.message !== error) {
      console.log(message);
    }
  }
  if (result !== valid) {
    // I don't want 100 failures, just give me one at a time. :)
    throw new Error("fail");
  }
});
