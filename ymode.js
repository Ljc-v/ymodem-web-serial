import { Buffer } from 'buffer';

// Constants for packet sizes and control characters
const PACKET_SIZE_128 = 128; // Packet size of 128 bytes
const PACKET_SIZE_1024 = 1024; // Packet size of 1024 bytes
const SOH = 0x01; // Start of Heading (SOH) character
const STX = 0x02; // Start of Text (STX) character
const EOT = 0x04; // End of Transmission (EOT) character
const ACK = 0x06; // Acknowledge (ACK) character
const NAK = 0x15; // Negative Acknowledge (NAK) character
const CA = 0x18; // Cancel (CA) character
const CRC16 = 0x43; // CRC16 character

// Predefined EOT packet
var eot_pack = Buffer.alloc(PACKET_SIZE_128 + 5, 0x00);
eot_pack[0] = SOH;
eot_pack[2] = 0xff;

/**
 * Calculate the CRC16-XModem checksum for a given packet.
 * @param {Buffer} packet - The buffer to calculate the CRC16 checksum for.
 * @param {number} begin - Starting index in the buffer.
 * @param {number} len - Length of data to include in the checksum calculation.
 * @param {number} [previous=0x0] - Previous CRC value to start with.
 * @returns {number} The calculated CRC16 checksum.
 */
function crc16xmodem(packet, begin, len, previous) {
    let stop_at = begin + len;
    let crc = typeof previous !== 'undefined' ? ~~previous : 0x0;
    for (; begin < stop_at; begin++) {
        let code = (crc >>> 8) & 0xff;
        code ^= packet[begin] & 0xff;
        code ^= code >>> 4;
        crc = (crc << 8) & 0xffff;
        crc ^= code;
        code = (code << 5) & 0xffff;
        crc ^= code;
        code = (code << 7) & 0xffff;
        crc ^= code;
    }
    return crc;
}

/**
 * Create a file header packet for YModem protocol.
 * @param {string} filename - Name of the file being transferred.
 * @param {number} filesize - Size of the file in bytes.
 * @returns {Buffer} The file header packet.
 */
function makeFileHeader(filename, filesize) {
    let File_HD_SIZE = 128;
    var payload = Buffer.alloc(File_HD_SIZE + 3 + 2, 0x00);
    payload[0] = SOH;
    payload[1] = 0;
    payload[2] = 0xff;
    var offset = 3;
    if (filename) {
        payload.write(filename, offset);
        offset += filename.length + 1;
    }
    if (filesize) {
        payload.write(filesize.toString() + " ", offset);
    }
    var crc = crc16xmodem(payload, 3, File_HD_SIZE);
    payload.writeUInt16BE(crc, payload.byteLength - 2);
    return payload;
}

/**
 * Split a file buffer into packets suitable for YModem transfer.
 * @param {Buffer} buffer - The file buffer to split.
 * @returns {Buffer[]} Array of packet buffers.
 */
function splitFile(buffer) {
    let totalBytes = buffer.byteLength;
    let maxPack = parseInt((buffer.byteLength + PACKET_SIZE_1024 - 1) / PACKET_SIZE_1024);
    var array = [];
    for (let i = 0; i < maxPack; i++) {
        let is_last = (i + 1) == maxPack ? true : false;
        let packSize = PACKET_SIZE_1024;
        if (is_last && totalBytes - i * PACKET_SIZE_1024 <= 128) {
            packSize = PACKET_SIZE_128;
        }
        var chunk = Buffer.alloc(packSize + 3 + 2, is_last ? 0x1A : 0x00);

        chunk[0] = (packSize == PACKET_SIZE_1024) ? STX : SOH;
        chunk[1] = (i + 1) & 0xff;
        chunk[2] = 0xff - chunk[1];

        buffer.copy(chunk, 3, PACKET_SIZE_1024 * i, PACKET_SIZE_1024 * i + packSize);
        var crc = crc16xmodem(chunk, 3, packSize);
        chunk.writeUInt16BE(crc, chunk.byteLength - 2);
        array.push(chunk);
    }
    return array;
}

/**
 * Split a buffer into chunks of specified size.
 * @param {Buffer} buffer - The buffer to split.
 * @param {number} size - Size of each chunk.
 * @returns {Buffer[]} Array of chunk buffers.
 */
function splitBuffer(buffer, size) {
    let totalBytes = buffer.byteLength;
    let maxPack = parseInt((buffer.byteLength + size - 1) / size);
    var array = [];
    for (let i = 0; i < maxPack; i++) {
        let is_last = (i + 1) == maxPack ? true : false;
        let packSize = size;
        if (is_last) {
            packSize = totalBytes % size;
        }
        var chunk = Buffer.alloc(packSize, 0x00);
        buffer.copy(chunk, 0, size * i, size * i + packSize);
        array.push(chunk);
    }
    return array;
}

/**
 * Transfer a file using the YModem protocol.
 * @param {{ reader: ReadableStreamDefaultReader, writer: WritableStreamDefaultWriter }} stream - Object containing reader and writer streams.
 * @param {string} filename - Name of the file being transferred.
 * @param {ArrayBuffer} buffer - The file buffer to transfer.
 * @param {Function} [logger=console.log] - Logging function.
 * @param {Function} [progressCallback] - Callback function for progress updates.
 * @returns {Promise<Object>} Promise that resolves with transfer result object.
 */
export function transfer({ reader, writer }, filename, buffer, logger = console.log, progressCallback) {
    return new Promise(async (resolve, reject) => {
        var file_trunks = [];
        var totalBytes = 0;
        var writtenBytes = 0;
        var seq = 0;
        var session = false;
        var sending = false;
        var finished = false;

        buffer = Buffer.from(buffer.buffer);

        /**
         * Send a buffer or its chunks to the writer.
         * @param {Buffer} buffer - The buffer to send.
         * @param {number} [once_len] - Optional chunk size for splitting the buffer.
         */
        async function sendBuffer(buffer, once_len = 0) {
            if (!once_len) {
                logger(`sendBuffer: Writing buffer of length ${buffer.length}`);
                await writer.write(buffer);
                return;
            }
            async function bulk() {
                var chunks = splitBuffer(buffer, once_len);
                for (const chunk of chunks) {
                    var arr = new Uint8Array(chunk.buffer);
                    await writer.write(arr);
                    logger(`sendBuffer: Writing chunk of length ${chunk.length}`);
                }
            }
            return await bulk();
        }

        /**
         * Send the next packet in sequence.
         */
        async function sendPacket() {
            logger(`sendPacket seq:${seq}/${file_trunks.length}`);
            if (seq < file_trunks.length) {
                var packet = file_trunks[seq];
                await sendBuffer(packet);
            } else {
                if (sending) {
                    await sendBuffer(Buffer.from([EOT]));
                    logger(`sendPacket: Sent EOT`);
                }
            }
        }

        /**
         * Read data from the reader and handle responses.
         */
        async function readData() {
            let PreChar = 0;
            try {
                while (true) {
                    const { value, done } = await reader.read();
                    if (done) {
                        break;
                    }
                    for (let i = 0; i < value.byteLength; i++) {
                        if (!finished) {
                            var ch = value[i];
                            logger(`RCV: ${String.fromCharCode(ch)} (${ch}) @${seq}`);
                            if (ch === CRC16) {
                                logger(`RCV: C @${seq}`);
                                if (seq >= file_trunks.length) {
                                    logger(`SEND EOT @${seq}`);
                                    sendBuffer(eot_pack);
                                } else if (PreChar != CRC16) {
                                    sendPacket();
                                    sending = true;
                                }
                            } else if (ch === ACK) {
                                logger(`RCV: ACK @${seq}`);
                                if (!session) {
                                    close();
                                }
                                if (sending) {
                                    if (seq == 0) { // HEADER ACK; DATA PACK followed by next C
                                        seq++;
                                    } else if (seq < file_trunks.length) {
                                        if (writtenBytes < totalBytes) {
                                            writtenBytes = (seq + 1) * PACKET_SIZE_1024;
                                            if (writtenBytes > totalBytes) {
                                                writtenBytes = totalBytes;
                                            }
                                            // onProgress && onProgress(writtenBytes / totalBytes);
                                        }
                                        seq++;
                                        if (progressCallback) {
                                             progressCallback((writtenBytes / totalBytes) * 100);
                                          }
                                        sendPacket();
                                    } else {
                                        sending = false;
                                        session = false;
                                        logger(`SEND EOT @${seq}`);
                                        sendBuffer(eot_pack);
                                    }
                                }
                            } else if (ch === NAK) {
                                logger(`RCV: NAK @${seq}`);
                                sendPacket();
                            } else if (ch === CA) {
                                logger(`RCV: CA @${seq}`);
                                close("CA");
                            }
                            PreChar = ch;
                        }
                    }
                }
            } catch (error) {
                reject(error);
            } finally {
                reader.releaseLock();
            }
        }

        /**
         * Close the transfer session.
         * @param {string} [ch=''] - Reason for closing.
         */
        function close(ch = '') {
            session = false;
            sending = false;
            if (reader.locked) {
                reader.cancel().then(() => {
                    logger(`CLOSE BY [${ch}]`);
                    finish();
                });
            } else {
                logger(`CLOSE BY [${ch}]`);
                finish();
            }
        }

        /**
         * Finish the transfer and resolve the promise.
         */
        function finish() {
            if (!finished) {
                const result = {
                    filePath: filename,
                    totalBytes: totalBytes,
                    writtenBytes: writtenBytes,
                };
                resolve(result);
            }
            finished = true;
        }

        totalBytes = buffer.byteLength;
        var headerPayload = makeFileHeader(filename, totalBytes);
        file_trunks.push(headerPayload);
        logger("File header created");

        var payloads = splitFile(buffer);
        payloads.forEach((payload) => {
            file_trunks.push(payload);
        });
        logger("File data packets created");

        session = true;
        readData();
        logger("YModem transfer session started");
    });
}