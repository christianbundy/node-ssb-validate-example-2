const fs = require('fs')

const str = fs.readFileSync('fixtures/messages.json', 'utf8')
const obj = JSON.parse(str)

const validHmac = obj.filter((item) => item.hmac !== null && item.valid === true)
const invalidHmac = obj.filter((item) => item.hmac !== null && item.valid === false)
const validNoHmac = obj.filter((item) => item.hmac === null && item.valid === true)
const invalidNoHmac = obj.filter((item) => item.hmac === null && item.valid === false)

// I think this has an increasing order or difficulty?
//
// 1. Pretend everything is valid
// 2. Deal with each invalid message
// 3. Add support for HMACs
// 4. Deal with each invalid message
//
const orderedResult = [
  ...validNoHmac,
  ...invalidNoHmac,
  ...validHmac,
  ...invalidHmac
]

const orderedResultString = JSON.stringify(orderedResult, null ,2)

fs.writeFileSync('fixtures/messages.json', orderedResultString)
