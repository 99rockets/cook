#!/usr/bin/env node
const crypto = require('crypto')
const sqlite3 = require('sqlite3').verbose()

const derivedKeySizeInBits = 128
const encryptionIterations = 1003
const encryptionVersionPrefix = "v10"

let cookiePath = null
let chromeKey = null
let filterHost = null
let filterName = null

const aesKey = (password, salt, done) => {
    return crypto.pbkdf2(password, salt, encryptionIterations, derivedKeySizeInBits / 8, 'sha1', done)
}

const decryptor = (key, iv, data) => {
    let decipher, decrypted, e, error1
    try {
        decipher = crypto.createDecipheriv('AES-128-CBC', key, iv)
        decrypted = decipher.update(data, 'binary', 'binary')
        return decrypted + decipher.final('binary')
    } catch (error1) {
        e = error1
        return console.log('error: ', e.message)
    }
}

const start = (path, pass) => {
    return aesKey(pass, 'saltysalt', (error, key) => {
        let db
        db = new sqlite3.Database(path, (error) => {
            if (error) {
                return console.log(error)
            }
        })
        return db.each("SELECT * from cookies", (err, row) => {
            let ret
            if (filterHost && row.host_key !== filterHost) {
                return
            }
            if (filterName && row.name !== filterName) {
                return
            }

            if (row.encrypted_value.indexOf(encryptionVersionPrefix) === 0) {
                row.encrypted_value = row.encrypted_value.slice(3)
            }

            const kIv = new Buffer('                ')
            ret = decryptor(key, kIv, row.encrypted_value)

            row.encrypted_value = ret
            if (filterName) {
                console.log(row.encrypted_value)
            } else {
                console.log(row)
            }
        })
    })
}

if (process.argv.length <= 2) {
    console.log("Command line: \n\t decryptor cookie-path chrome-key [cookie-host] [cookie-name]\n")
    console.log("Get chrome key (OS X): \n\t security find-generic-password -w -s \"Chrome Safe Storage\"")
} else {
    cookiePath = process.argv[2]
    chromeKey = process.argv[3]
    filterHost = process.argv[4]
    filterName = process.argv[5]
    start(cookiePath, chromeKey)
}
