const readline = require('readline')
const { getValidationError } = require('.')

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

const data = []

rl.on('line', (line) => {
  data.push(line)
})

rl.on('close', () => {
  const entry = JSON.parse(data.join(''))
  try {
    const { message, state, hmacKey } = entry
    const error = getValidationError(message, state, hmacKey)
    console.log(error)
    if (error === null) {
      process.exit(0)
    } else {
      process.exit(1)
    }
  } catch (e) {
    console.log(e)
    process.exit(1)
  }
})
