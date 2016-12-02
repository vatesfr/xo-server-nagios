import { Buffer } from 'buffer'
import net from 'net'
import crc32 from 'buffer-crc32'

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
      description: 'The snca port'
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
export const testSchema = {
  type: 'object',

  properties: {
    status: {
      type: 'integer',
      description: 'The service status in Nagios (0: OK | 1: WARNING | 2: CRITICAL)'
    }
  },
  additionalProperties: false,
  required: ['status']
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

  test ({status}) {
    return this._sendPassiveCheck(status, 'The server-nagios plugin for Xen Orchestra server seems to be working fine, nicely done :)')
  }

  _sendPassiveCheck (status, message) {
    const client = new net.Socket()
    client.connect(this._conf.port, this._conf.server, () => {
      console.log('Successful connection')
    })
    client.on('data', data => {
      const encoding = 'binary'
      const dataBuffer = new Buffer(data)
      const iv = dataBuffer.toString(encoding, 0, 128) // initialization vector
      const timestamp = dataBuffer.readInt32BE(128)
      const paquet = this._nscaPaquetBuilder(SIZE, VERSION, timestamp, iv, status, message, encoding)
      // 1) Using xor between the NSCA paquet and the initialization vector
      // 2) Using xor between the result of the first operation and the encryption key
      const xorPaquetBuffer = new Buffer(this._xor(this._xor(this._stringToAsciiArray(paquet.toString(encoding)), this._stringToAsciiArray(iv)), this._stringToAsciiArray(this._conf.key)), encoding)
      client.write(xorPaquetBuffer, function (a) {
        client.destroy()
      })
    })
  }

  _nscaPaquetBuilder (size, version, timestamp, iv, status, message, encoding) {
    // Building nsca paquet
    const paquet = new Buffer(size)
    paquet.fill(0)
    paquet.writeInt16BE(version, 0)
    paquet.fill('h', 2, 3)
    paquet.writeUInt32BE(0, 4) // initial 0 for CRC32 value
    paquet.writeUInt32BE(timestamp, 8)
    paquet.writeInt16BE(status, 12)
    paquet.write(this._conf.host, 14, 77, encoding)
    paquet.write(this._conf.service, 78, 206, encoding)
    paquet.write(message, 206, size, encoding)
    paquet.writeUInt32BE(crc32.unsigned(paquet), 4)
    return paquet
  }

  _stringToAsciiArray (str) {
    const map = Array.prototype.map
    const chars = map.call(str, x => {
      return x.charCodeAt(0)
    })
    return chars
  }

  _xor (long, short) {
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
}

export default opts => new XoServerNagios(opts)
