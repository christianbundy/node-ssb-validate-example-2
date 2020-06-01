const tap = require("tap");
const fs = require("fs");
const isValid = require("./");

const isValidWord = {
  true: "valid",
  false: "invalid",
};

const messages = JSON.parse(fs.readFileSync("fixtures/messages.json", "utf8"));
messages.forEach(({ state, value, hmacKey, valid }) => {
  const result = isValid(value, state != null ? state : undefined, hmacKey);

  tap.equal(result, valid, `Message should be ${isValidWord[valid]}`, {
    value,
    state,
    hmacKey,
  });
  if (result !== valid) {
    // I don't want 100 failures, just give me one at a time. :)
    throw new Error("fail");
  }
});
