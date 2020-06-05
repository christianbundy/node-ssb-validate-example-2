const fs = require("fs");
const crypto = require('crypto')

const str = fs.readFileSync("fixtures/messages.json", "utf8");

const hash = (inputObj) => {
  const string = JSON.stringify(inputObj, null, 2)
  const bytes = Buffer.from(string, 'latin1')
  const hash = crypto.createHash('sha256').update(bytes).digest('base64')
  return `%${hash}.sha256`
}

const obj = JSON.parse(str).map((item) => {
  item.id = hash(item.message)
  return item
})

const result = JSON.stringify(obj, null, 2);

fs.writeFileSync("fixtures/messages.json", result);
