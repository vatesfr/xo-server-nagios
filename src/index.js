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

function nscaPacketBuilder (host, service, size, version, timestamp, iv, status, message, encoding) {
  // Building NSCA packet
  let packet = new Buffer(size)
  packet.fill(0)
  packet.writeInt16BE(version, 0)
  packet.fill('h', 2, 3)
  packet.writeUInt32BE(0, 4) // initial 0 for CRC32 value
  packet.writeUInt32BE(timestamp, 8)
  packet.writeInt16BE(status, 12)
  packet.write(host, 14, 77, encoding)
  packet.write(service, 78, 206, encoding)
  packet.write(message, 206, size, encoding)
  packet.writeUInt32BE(crc32.unsigned(packet), 4)
  packet = Buffer.from(packet.toString(encoding), 'ascii')
  return packet
}

function xor (long, short) {
  const result = []
  let j = 0
  for (let i = 0; i < long.length; i++) {
    if (j === short.length) {
      j = 0
    }
    result[i] = long[i] ^ short[j]
    j++
  }
  return result
}

// ===================================================================

const SIZE = 720
const VERSION = 3

class XoServerNagios {

  constructor ({ xo }) {
    this._sendPassiveCheck = ::this._sendPassiveCheck
    this._set = ::xo.defineProperty
    this._unset = null

   // Defined in configure().
    this._conf = null
  }

  configure (configuration) {
    this._conf = configuration
  }

  load () {
    this._unset = this._set('sendPassiveCheck', this._sendPassiveCheck)
  }

  unload () {
    this._unset()
  }

  test () {
    return this._sendPassiveCheck({
      status: 0,
      message: 'The server-nagios plugin for Xen Orchestra server seems to be working fine, nicely done :)'
    })
  }

  _sendPassiveCheck ({
    status,
    message
  }) {
    const client = new net.Socket()

    return new Promise((resolve, reject) => {
      client.connect(this._conf.port, this._conf.server, () => {
        console.log('Successful connection')
      })

      client.on('data', data => {
        const encoding = 'binary'
        const timestamp = data.readInt32BE(128)
        const packet = nscaPacketBuilder(this._conf.host, this._conf.service, SIZE, VERSION, timestamp, iv, status, message.toString().replace(/\s/g, ' '), encoding)
        const iv = Buffer.from(data.toString(encoding, 0, 128), 'ascii') // initialization vector
        const key = Buffer.from(this._conf.key, 'ascii')

        // 1) Using xor between the NSCA packet and the initialization vector
        // 2) Using xor between the result of the first operation and the encryption key
        const xorPacketBuffer = new Buffer(
          xor(
            xor(
              packet,
              iv
            ),
            key
          ),
          encoding
        )
        client.write(xorPacketBuffer, (a) => {
          client.destroy()
          resolve(a)
        })
      })

      client.on('error', (err) => {
        reject(err)
      })
    })
  }
}

export default opts => new XoServerNagios(opts)
