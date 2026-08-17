// One error type with a machine-readable code, because both transports have to turn failures into
// something structured: MCP returns them as tool errors, the hub as JSON with an HTTP status.

export class ArgusError extends Error {
  constructor(code, message, detail = {}) {
    super(message)
    this.name = 'ArgusError'
    this.code = code
    this.detail = detail
  }

  get httpStatus() {
    return {
      CONFIG_INVALID: 500,
      DRIVER_UNKNOWN: 500,
      DEVICE_UNKNOWN: 404,
      CAPABILITY_UNKNOWN: 404,
      INPUT_INVALID: 400,
      CONFIRM_REQUIRED: 428,
      GUARDED: 403,
      UNREACHABLE: 502,
      AUTH_FAILED: 502,
      DEVICE_REFUSED: 502,
    }[this.code] ?? 500
  }

  toJSON() {
    return { error: this.code, message: this.message, ...this.detail }
  }
}

export const fail = (code, message, detail) => { throw new ArgusError(code, message, detail) }
