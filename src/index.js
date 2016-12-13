import crc32 from 'buffer-crc32'
import net from 'net'
import { Buffer } from 'buffer'

// ===================================================================

export const configurationSchema = {
  type: 'object',

  properties: {
    server: {
      type: 'string',
      description: 'The nagios server adress'
    },
    port: {
      type: 'integer',
      description: 'The NSCA port'
    },
    key: {
      type: 'string',
      description: 'The encryption key'
    },
    host: {
      type: 'string',
      description: 'The host name in Nagios'
    },
    service: {
      type: 'string',
      description: 'The service description in Nagios'
    }
  },
  additionalProperties: false,
  required: ['server', 'port', 'key', 'host', 'service']
}

// ===================================================================

function nscaPacketBuilder ({
  encoding,
  host,
  iv,
  message,
  service,
  status,
  timestamp,
  version
}) {
  // Building NSCA packet
  const SIZE = 720
  const packet = new Buffer(SIZE)
  packet.fill(0)
  packet.writeInt16BE(version, 0)
  packet.fill('h', 2, 3)
  packet.writeUInt32BE(0, 4) // initial 0 for CRC32 value
  packet.writeUInt32BE(timestamp, 8)
  packet.writeInt16BE(status, 12)
  packet.write(host, 14, 77, encoding)
  packet.write(service, 78, 206, encoding)
  packet.write(message, 206, SIZE, encoding)
  packet.writeUInt32BE(crc32.unsigned(packet), 4)
  return packet
}

function xor (data, mask) {
  const result = new Buffer(data.length)
  const dataSize = data.length
  const maskSize = mask.length
  let j = 0
  for (let i = 0; i < dataSize; i++) {
    if (j === maskSize) {
      j = 0
    }
    result[i] = data[i] ^ mask[j]
    j++
  }
  return result
}

// ===================================================================

export const OK = 0
export const WARNING = 1
export const CRITICAL = 2

const VERSION = 3
const ENCODING = 'binary'

class XoServerNagios {

  constructor ({ xo }) {
    this._sendPassiveCheck = ::this._sendPassiveCheck
    this._set = ::xo.defineProperty
    this._unset = null

   // Defined in configure().
    this._conf = null
    this._key = null
  }

  configure (configuration) {
    this._conf = configuration
    this._key = new Buffer(configuration.key, ENCODING)
  }

  load () {
    this._unset = this._set('sendPassiveCheck', this._sendPassiveCheck)
  }

  unload () {
    this._unset()
  }

  test () {
    return this._sendPassiveCheck({
      message: 'The server-nagios plugin for Xen Orchestra server seems to be working fine, nicely done :)',
      status: OK
    })
  }

  _sendPassiveCheck ({
    message,
    status
  }) {
    const client = new net.Socket()

    return new Promise((resolve, reject) => {
      client.connect(this._conf.port, this._conf.server, () => {
        console.log('Successful connection')
      })

      client.on('data', data => {
        const timestamp = data.readInt32BE(128)
        const iv = new Buffer(data.slice(0, 128), ENCODING) // initialization vector
        const packet = nscaPacketBuilder({
          ...this._conf,
          encoding: ENCODING,
          iv,
          message: message.toString().replace(/\s/g, ' '),
          status,
          timestamp,
          version: VERSION
        })

        // 1) Using xor between the NSCA packet and the initialization vector
        // 2) Using xor between the result of the first operation and the encryption key
        const xorPacketBuffer = new Buffer(
          xor(
            xor(
              packet,
              iv
            ),
            this._key
          ),
          ENCODING
        )
        client.write(xorPacketBuffer, res => {
          client.destroy()
          resolve(res)
        })
      })

      client.on('error', reject)
    })
  }
}

export default opts => new XoServerNagios(opts)
