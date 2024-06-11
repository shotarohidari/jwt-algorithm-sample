import { createHmac } from "node:crypto"

type Data = { [key: string]: string | boolean }

const header = {
  alg: "HS256",
  typ: "JWT",
} satisfies Data

const payload = {
  sub: "1234567890",
  name: "John Doe",
  admin: true,
} satisfies Data

// ascii
const secret = "hello"
const signature = dataToJWTsignature({ header, payload, secret })

function dataToJWTsignature({
  header,
  payload,
  secret,
}: {
  header: Data
  payload: Data
  secret: string
}) {
  const encoder = new TextEncoder()

  const encodedHeader = btoa(
    Array.from(encoder.encode(JSON.stringify(header)), (byte) =>
      String.fromCharCode(byte)
    ).join("")
  )
  const encodedPayload = btoa(
    Array.from(encoder.encode(JSON.stringify(payload)), (byte) =>
      String.fromCharCode(byte)
    ).join("")
  )

  const hmac = createHmac("sha256", secret)
  const signature = hmac
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest("base64url")

  const debug = true
  if (debug) {
    console.log({ encodedHeader, encodedPayload, signature })
  }
  return signature
}
