// База версии основана на коммите 43fad05dcdae3b723c53c226f8181fc5bd47223e, дата: 2023-06-22 15:20:02 UTC
// @ts-ignore
import { connect } from "cloudflare:sockets";

// Как сгенерировать собственный UUID:
// [Windows] Нажмите "Win + R", введите cmd и выполните: Powershell -NoExit -Command "[guid]::NewGuid()"
let userID = "86c50e3a-5b87-49dd-bd20-03c7f2735e40";

const proxyIPs = ["xjp.ygkkk.dpdns.org:60360"];
const cn_hostnames = [''];
let CDNIP = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0073\u0067'
// http_ip
let IP1 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP2 = '\u0063\u0069\u0073\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP3 = '\u0061\u0066\u0072\u0069\u0063\u0061\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP4 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0073\u0067'
let IP5 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u0065\u0075\u0072\u006f\u0070\u0065\u002e\u0061\u0074'
let IP6 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u006d\u0074'
let IP7 = '\u0071\u0061\u002e\u0076\u0069\u0073\u0061\u006d\u0069\u0064\u0064\u006c\u0065\u0065\u0061\u0073\u0074\u002e\u0063\u006f\u006d'

// https_ip
let IP8 = '\u0075\u0073\u0061\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP9 = '\u006d\u0079\u0061\u006e\u006d\u0061\u0072\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d'
let IP10 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0074\u0077'
let IP11 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u0065\u0075\u0072\u006f\u0070\u0065\u002e\u0063\u0068'
let IP12 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u002e\u0063\u006f\u006d\u002e\u0062\u0072'
let IP13 = '\u0077\u0077\u0077\u002e\u0076\u0069\u0073\u0061\u0073\u006f\u0075\u0074\u0068\u0065\u0061\u0073\u0074\u0065\u0075\u0072\u006f\u0070\u0065\u002e\u0063\u006f\u006d'

// http_port
let PT1 = '80'
let PT2 = '8080'
let PT3 = '8880'
let PT4 = '2052'
let PT5 = '2082'
let PT6 = '2086'
let PT7 = '2095'

// https_port
let PT8 = '443'
let PT9 = '8443'
let PT10 = '2053'
let PT11 = '2083'
let PT12 = '2087'
let PT13 = '2096'

let proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
let proxyPort = proxyIP.match(/:(\d+)$/) ? proxyIP.match(/:(\d+)$/)[1] : '443';
const dohURL = "https://cloudflare-dns.com/dns-query";
if (!isValidUUID(userID)) {
  throw new Error("UUID недействителен");
}

export default {
  /**
   * @param {any} request
   * @param {{uuid: string, proxyip: string, cdnip: string, ip1: string, ip2: string, ip3: string, ip4: string, ip5: string, ip6: string, ip7: string, ip8: string, ip9: string, ip10: string, ip11: string, ip12: string, ip13: string, pt1: string, pt2: string, pt3: string, pt4: string, pt5: string, pt6: string, pt7: string, pt8: string, pt9: string, pt10: string, pt11: string, pt12: string, pt13: string}} env
   * @param {any} ctx
   * @returns {Promise<Response>}
   */
  async fetch(request, env, ctx) {
    try {
      const { proxyip } = env;
      userID = env.uuid || userID;
      if (proxyip) {
        if (proxyip.includes(']:')) {
          let lastColonIndex = proxyip.lastIndexOf(':');
          proxyPort = proxyip.slice(lastColonIndex + 1);
          proxyIP = proxyip.slice(0, lastColonIndex);
        } else if (!proxyip.includes(']:') && !proxyip.includes(']')) {
          [proxyIP, proxyPort = '443'] = proxyip.split(':');
        } else {
          proxyPort = '443';
          proxyIP = proxyip;
        }
      } else {
        if (proxyIP.includes(']:')) {
          let lastColonIndex = proxyIP.lastIndexOf(':');
          proxyPort = proxyIP.slice(lastColonIndex + 1);
          proxyIP = proxyIP.slice(0, lastColonIndex);
        } else {
          const match = proxyIP.match(/^(.*?)(?::(\d+))?$/);
          proxyIP = match[1];
          let proxyPort = match[2] || '443';
          console.log("IP:", proxyIP, "Порт:", proxyPort);
        }
      }
      console.log('ProxyIP:', proxyIP);
      console.log('ProxyPort:', proxyPort);
      CDNIP = env.cdnip || CDNIP;
      IP1 = env.ip1 || IP1;
      IP2 = env.ip2 || IP2;
      IP3 = env.ip3 || IP3;
      IP4 = env.ip4 || IP4;
      IP5 = env.ip5 || IP5;
      IP6 = env.ip6 || IP6;
      IP7 = env.ip7 || IP7;
      IP8 = env.ip8 || IP8;
      IP9 = env.ip9 || IP9;
      IP10 = env.ip10 || IP10;
      IP11 = env.ip11 || IP11;
      IP12 = env.ip12 || IP12;
      IP13 = env.ip13 || IP13;
      PT1 = env.pt1 || PT1;
      PT2 = env.pt2 || PT2;
      PT3 = env.pt3 || PT3;
      PT4 = env.pt4 || PT4;
      PT5 = env.pt5 || PT5;
      PT6 = env.pt6 || PT6;
      PT7 = env.pt7 || PT7;
      PT8 = env.pt8 || PT8;
      PT9 = env.pt9 || PT9;
      PT10 = env.pt10 || PT10;
      PT11 = env.pt11 || PT11;
      PT12 = env.pt12 || PT12;
      PT13 = env.pt13 || PT13;
      const upgradeHeader = request.headers.get("Upgrade");
      const url = new URL(request.url);
      if (!upgradeHeader || upgradeHeader !== "websocket") {
        const url = new URL(request.url);
        switch (url.pathname) {
          case `/${userID}`: {
            const vlessConfig = getVlessConfig(userID, request.headers.get("Host"));
            return new Response(`${vlessConfig}`, {
              status: 200,
              headers: {
                "Content-Type": "text/html;charset=utf-8",
              },
            });
          }
          case `/${userID}/ty`: {
            const tyConfig = gettyConfig(userID, request.headers.get('Host'));
            return new Response(`${tyConfig}`, {
              status: 200,
              headers: {
                "Content-Type": "text/plain;charset=utf-8",
              }
            });
          }
          case `/${userID}/cl`: {
            const clConfig = getclConfig(userID, request.headers.get('Host'));
            return new Response(`${clConfig}`, {
              status: 200,
              headers: {
                "Content-Type": "text/plain;charset=utf-8",
              }
            });
          }
          case `/${userID}/sb`: {
            const sbConfig = getsbConfig(userID, request.headers.get('Host'));
            return new Response(`${sbConfig}`, {
              status: 200,
              headers: {
                "Content-Type": "application/json;charset=utf-8",
              }
            });
          }
          case `/${userID}/pty`: {
            const ptyConfig = getptyConfig(userID, request.headers.get('Host'));
            return new Response(`${ptyConfig}`, {
              status: 200,
              headers: {
                "Content-Type": "text/plain;charset=utf-8",
              }
            });
          }
          case `/${userID}/pcl`: {
            const pclConfig = getpclConfig(userID, request.headers.get('Host'));
            return new Response(`${pclConfig}`, {
              status: 200,
              headers: {
                "Content-Type": "text/plain;charset=utf-8",
              }
            });
          }
          case `/${userID}/psb`: {
            const psbConfig = getpsbConfig(userID, request.headers.get('Host'));
            return new Response(`${psbConfig}`, {
              status: 200,
              headers: {
                "Content-Type": "application/json;charset=utf-8",
              }
            });
          }
          default:
            // return new Response('Не найдено', { status: 404 });
            // Для любого другого пути перенаправляем запрос на случайный веб-сайт и возвращаем исходный ответ, кэшируя его
            if (cn_hostnames.includes('')) {
            return new Response(JSON.stringify(request.cf, null, 4), {
              status: 200,
              headers: {
                "Content-Type": "application/json;charset=utf-8",
              },
            });
            }
            const randomHostname = cn_hostnames[Math.floor(Math.random() * cn_hostnames.length)];
            const newHeaders = new Headers(request.headers);
            newHeaders.set("cf-connecting-ip", "1.2.3.4");
            newHeaders.set("x-forwarded-for", "1.2.3.4");
            newHeaders.set("x-real-ip", "1.2.3.4");
            newHeaders.set("referer", "https://www.google.com/search?q=edtunnel");
            // Используем fetch для перенаправления запроса на 15 различных доменов
            const proxyUrl = "https://" + randomHostname + url.pathname + url.search;
            let modifiedRequest = new Request(proxyUrl, {
              method: request.method,
              headers: newHeaders,
              body: request.body,
              redirect: "manual",
            });
            const proxyResponse = await fetch(modifiedRequest, { redirect: "manual" });
            // Проверяем статус перенаправления 302 или 301 и возвращаем ошибку
            if ([301, 302].includes(proxyResponse.status)) {
              return new Response(`Перенаправление на ${randomHostname} не разрешено.`, {
                status: 403,
                statusText: "Запрещено",
              });
            }
            // Возвращаем ответ от прокси-сервера
            return proxyResponse;
        }
      } else {
        if(url.pathname.includes('/pyip=')) {
          const tmp_ip=url.pathname.split("=")[1];
          if(isValidIP(tmp_ip)) {
            proxyIP=tmp_ip;
            if (proxyIP.includes(']:')) {
              let lastColonIndex = proxyIP.lastIndexOf(':');
              proxyPort = proxyIP.slice(lastColonIndex + 1);
              proxyIP = proxyIP.slice(0, lastColonIndex);
            } else if (!proxyIP.includes(']:') && !proxyIP.includes(']')) {
              [proxyIP, proxyPort = '443'] = proxyIP.split(':');
            } else {
              proxyPort = '443';
            }
          }
        }
        return await vlessOverWSHandler(request);
      }
    } catch (err) {
      /** @type {Error} */ let e = err;
      return new Response(e.toString());
    }
  },
};

function isValidIP(ip) {
    var reg = /^[\s\S]*$/;
    return reg.test(ip);
}

/**
 * Обработчик WebSocket для VLESS
 * @param {any} request
 */
async function vlessOverWSHandler(request) {
  /** @type {any} */
  // @ts-ignore
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);

  webSocket.accept();

  let address = "";
  let portWithRandomLog = "";
  const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
  };
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";

  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

  /** @type {{ value: any | null }} */
  let remoteSocketWapper = {
    value: null,
  };
  let udpStreamWrite = null;
  let isDns = false;

  // ws --> remote
  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (isDns && udpStreamWrite) {
            return udpStreamWrite(chunk);
          }
          if (remoteSocketWapper.value) {
            const writer = remoteSocketWapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const {
            hasError,
            message,
            portRemote = 443,
            addressRemote = "",
            rawDataIndex,
            cloudflareVersion = new Uint8Array([0, 0]),
            isUDP,
          } = await processcloudflareHeader(chunk, userID);
          address = addressRemote;
          portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? "udp " : "tcp "} `;
          if (hasError) {
            throw new Error(message);
            return;
          }
          // Если UDP, но порт не DNS, закрываем соединение
          if (isUDP) {
            if (portRemote === 53) {
              isDns = true;
            } else {
              throw new Error("UDP-прокси поддерживается только для DNS (порт 53)");
              return;
            }
          }
          // ["версия", "длина дополнительной информации N"]
          const cloudflareResponseHeader = new Uint8Array([cloudflareVersion[0], 0]);
          const rawClientData = chunk.slice(rawDataIndex);

          // TODO: поддержка UDP, когда Cloudflare добавит поддержку UDP
          if (isDns) {
            const { write } = await handleUDPOutBound(webSocket, cloudflareResponseHeader, log);
            udpStreamWrite = write;
            udpStreamWrite(rawClientData);
            return;
          }
          handleTCPOutBound(
            remoteSocketWapper,
            addressRemote,
            portRemote,
            rawClientData,
            webSocket,
            cloudflareResponseHeader,
            log
          );
        },
        close() {
          log(`Поток readableWebSocketStream закрыт`);
        },
        abort(reason) {
          log(`Поток readableWebSocketStream прерван`, JSON.stringify(reason));
        },
      })
    )
    .catch((err) => {
      log("Ошибка в pipeTo readableWebSocketStream", err);
    });

  return new Response(null, {
    status: 101,
    // @ts-ignore
    webSocket: client,
  });
}

/**
 * Проверяет, присутствует ли указанный UUID в ответе API.
 * @param {string} targetUuid UUID для поиска.
 * @returns {Promise<boolean>} Возвращает true, если UUID найден в ответе API, иначе false.
 */
async function checkUuidInApiResponse(targetUuid) {
  try {
    const apiResponse = await getApiResponse();
    if (!apiResponse) {
      return false;
    }
    const isUuidInResponse = apiResponse.users.some((user) => user.uuid === targetUuid);
    return isUuidInResponse;
  } catch (error) {
    console.error("Ошибка:", error);
    return false;
  }
}

async function getApiResponse() {
  return { users: [] };
}

/**
 * Обрабатывает исходящие TCP-соединения.
 * @param {any} remoteSocket
 * @param {string} addressRemote Удаленный адрес для подключения.
 * @param {number} portRemote Удаленный порт для подключения.
 * @param {Uint8Array} rawClientData Исходные данные клиента для записи.
 * @param {any} webSocket WebSocket для передачи удаленного сокета.
 * @param {Uint8Array} cloudflareResponseHeader Заголовок ответа Cloudflare.
 * @param {function} log Функция логирования.
 * @returns {Promise<void>} Удаленный сокет.
 */
async function handleTCPOutBound(
  remoteSocket,
  addressRemote,
  portRemote,
  rawClientData,
  webSocket,
  cloudflareResponseHeader,
  log
) {
  async function connectAndWrite(address, port) {
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(address)) address = `${atob('d3d3Lg==')}${address}${atob('LnNzbGlwLmlv')}`;
    /** @type {any} */
    const tcpSocket = connect({
      hostname: address,
      port: port,
    });
    remoteSocket.value = tcpSocket;
    log(`Подключено к ${address}:${port}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData); // Первая запись, обычно TLS Client Hello
    writer.releaseLock();
    return tcpSocket;
  }

  // Если TCP-сокет Cloudflare не получает входящих данных, пробуем перенаправить IP
  async function retry() {
    const tcpSocket = await connectAndWrite(proxyIP || addressRemote, proxyPort || portRemote);
    // Независимо от успеха повторной попытки, закрываем WebSocket
    tcpSocket.closed
      .catch((error) => {
        console.log("Ошибка закрытия tcpSocket при повторной попытке", error);
      })
      .finally(() => {
        safeCloseWebSocket(webSocket);
      });
    remoteSocketToWS(tcpSocket, webSocket, cloudflareResponseHeader, null, log);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);

  // Когда удаленный сокет готов, передаем его в WebSocket
  // remote --> ws
  remoteSocketToWS(tcpSocket, webSocket, cloudflareResponseHeader, retry, log);
}

/**
 * Создает читаемый поток WebSocket.
 * @param {any} webSocketServer Сервер WebSocket.
 * @param {string} earlyDataHeader Заголовок ранних данных для WebSocket 0RTT.
 * @param {(info: string)=> void} log Функция логирования для WebSocket 0RTT.
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (readableStreamCancel) {
          return;
        }
        const message = event.data;
        controller.enqueue(message);
      });

      // Событие означает, что клиент закрыл поток клиент -> сервер.
      // Однако поток сервер -> клиент остается открытым, пока не будет вызван close() на стороне сервера.
      webSocketServer.addEventListener("close", () => {
        // Клиент отправил закрытие, нужно закрыть сервер
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) {
          return;
        }
        controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        log("Ошибка сервера WebSocket");
        controller.error(err);
      });
      // Для WebSocket 0RTT
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },

    pull(controller) {
      // Если WebSocket может остановить чтение при полном потоке, можно реализовать обратное давление
    },
    cancel(reason) {
      // 1. Ошибка в pipe WritableStream вызывает cancel
      // 2. Если readableStream отменен, все controller.close/enqueue нужно пропустить
      // 3. controller.error продолжает работать даже при отмене readableStream
      if (readableStreamCancel) {
        return;
      }
      log(`Чтение потока было отменено из-за ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });

  return stream;
}

/**
 * Обрабатывает заголовок Cloudflare.
 * @param {ArrayBuffer} cloudflareBuffer Буфер Cloudflare.
 * @param {string} userID Идентификатор пользователя.
 * @returns Объект с информацией о заголовке.
 */
async function processcloudflareHeader(cloudflareBuffer, userID) {
  if (cloudflareBuffer.byteLength < 24) {
    return {
      hasError: true,
      message: "Недействительные данные",
    };
  }
  const version = new Uint8Array(cloudflareBuffer.slice(0, 1));
  let isValidUser = false;
  let isUDP = false;
  const slicedBuffer = new Uint8Array(cloudflareBuffer.slice(1, 17));
  const slicedBufferString = stringify(slicedBuffer);

  const uuids = userID.includes(",") ? userID.split(",") : [userID];

  const checkUuidInApi = await checkUuidInApiResponse(slicedBufferString);
  isValidUser = uuids.some((userUuid) => checkUuidInApi || slicedBufferString === userUuid.trim());

  console.log(`checkUuidInApi: ${await checkUuidInApiResponse(slicedBufferString)}, userID: ${slicedBufferString}`);

  if (!isValidUser) {
    return {
      hasError: true,
      message: "Недействительный пользователь",
    };
  }

  const optLength = new Uint8Array(cloudflareBuffer.slice(17, 18))[0];
  // Пропускаем дополнительные опции

  const command = new Uint8Array(cloudflareBuffer.slice(18 + optLength, 18 + optLength + 1))[0];

  // 0x01 TCP
  // 0x02 UDP
  // 0x03 MUX
  if (command === 1) {
  } else if (command === 2) {
    isUDP = true;
  } else {
    return {
      hasError: true,
      message: `Команда ${command} не поддерживается, поддерживаются: 01-tcp, 02-udp, 03-mux`,
    };
  }
  const portIndex = 18 + optLength + 1;
  const portBuffer = cloudflareBuffer.slice(portIndex, portIndex + 2);
  // Порт в формате big-Endian, например, 80 == 0x005d
  const portRemote = new DataView(portBuffer).getUint16(0);

  let addressIndex = portIndex + 2;
  const addressBuffer = new Uint8Array(cloudflareBuffer.slice(addressIndex, addressIndex + 1));

  // 1 --> ipv4, addressLength = 4
  // 2 --> доменное имя, addressLength = addressBuffer[1]
  // 3 --> ipv6, addressLength = 16
  const addressType = addressBuffer[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(cloudflareBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 2:
      addressLength = new Uint8Array(cloudflareBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(cloudflareBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3:
      addressLength = 16;
      const dataView = new DataView(cloudflareBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      // 2001:0db8:85a3:0000:0000:8a2e:0370:7334
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `Недействительный тип адреса: ${addressType}`,
      };
  }
  if (!addressValue) {
    return {
      hasError: true,
      message: `Значение адреса пустое, тип адреса: ${addressType}`,
    };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    cloudflareVersion: version,
    isUDP,
  };
}

/**
 * Передает данные от удаленного сокета в WebSocket.
 * @param {any} remoteSocket Удаленный сокет.
 * @param {any} webSocket WebSocket.
 * @param {ArrayBuffer} cloudflareResponseHeader Заголовок ответа Cloudflare.
 * @param {(() => Promise<void>) | null} retry Функция повторной попытки.
 * @param {*} log Функция логирования.
 */
async function remoteSocketToWS(remoteSocket, webSocket, cloudflareResponseHeader, retry, log) {
  // remote --> ws
  let remoteChunkCount = 0;
  let chunks = [];
  /** @type {ArrayBuffer | null} */
  let cloudflareHeader = cloudflareResponseHeader;
  let hasIncomingData = false; // Проверяем, есть ли входящие данные от удаленного сокета
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        start() {},
        /**
         * @param {Uint8Array} chunk
         * @param {*} controller
         */
        async write(chunk, controller) {
          hasIncomingData = true;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error("WebSocket не открыт, возможно, закрыт");
          }
          if (cloudflareHeader) {
            webSocket.send(await new Blob([cloudflareHeader, chunk]).arrayBuffer());
            cloudflareHeader = null;
          } else {
            webSocket.send(chunk);
          }
        },
        close() {
          log(`readable удаленного соединения закрыт, hasIncomingData: ${hasIncomingData}`);
        },
        abort(reason) {
          console.error(`Прерывание readable удаленного соединения`, reason);
        },
      })
    )
    .catch((error) => {
      console.error(`Ошибка в remoteSocketToWS`, error.stack || error);
      safeCloseWebSocket(webSocket);
    });

  // Если нет входящих данных и есть функция retry, выполняем повторную попытку
  if (hasIncomingData === false && retry) {
    log(`Повторная попытка`);
    retry();
  }
}

/**
 * Преобразует строку base64 в ArrayBuffer.
 * @param {string} base64Str Строка в формате base64.
 * @returns Объект с ранними данными или ошибкой.
 */
function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

/**
 * Проверяет валидность UUID.
 * @param {string} uuid UUID для проверки.
 */
function isValidUUID(uuid) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
/**
 * Безопасно закрывает WebSocket.
 * @param {any} socket Сокет для закрытия.
 */
function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error("Ошибка при безопасном закрытии WebSocket", error);
  }
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 256).toString(16).slice(1));
}
function unsafeStringify(arr, offset = 0) {
  return (
    byteToHex[arr[offset + 0]] +
    byteToHex[arr[offset + 1]] +
    byteToHex[arr[offset + 2]] +
    byteToHex[arr[offset + 3]] +
    "-" +
    byteToHex[arr[offset + 4]] +
    byteToHex[arr[offset + 5]] +
    "-" +
    byteToHex[arr[offset + 6]] +
    byteToHex[arr[offset + 7]] +
    "-" +
    byteToHex[arr[offset + 8]] +
    byteToHex[arr[offset + 9]] +
    "-" +
    byteToHex[arr[offset + 10]] +
    byteToHex[arr[offset + 11]] +
    byteToHex[arr[offset + 12]] +
    byteToHex[arr[offset + 13]] +
    byteToHex[arr[offset + 14]] +
    byteToHex[arr[offset + 15]]
  ).toLowerCase();
}
function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) {
    throw TypeError("Преобразованный UUID недействителен");
  }
  return uuid;
}

/**
 * Обрабатывает исходящие UDP-соединения (только для DNS).
 * @param {any} webSocket WebSocket.
 * @param {ArrayBuffer} cloudflareResponseHeader Заголовок ответа Cloudflare.
 * @param {(string)=> void} log Функция логирования.
 */
async function handleUDPOutBound(webSocket, cloudflareResponseHeader, log) {
  let iscloudflareHeaderSent = false;
  const transformStream = new TransformStream({
    start(controller) {},
    transform(chunk, controller) {
      // UDP-сообщение: первые 2 байта — длина данных UDP
      for (let index = 0; index < chunk.byteLength; ) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
        const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPakcetLength));
        index = index + 2 + udpPakcetLength;
        controller.enqueue(udpData);
      }
    },
    flush(controller) {},
  });

  // Обрабатываем только DNS UDP
  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          const resp = await fetch(
            dohURL, // URL DNS-сервера
            {
              method: "POST",
              headers: {
                "content-type": "application/dns-message",
              },
              body: chunk,
            }
          );
          const dnsQueryResult = await resp.arrayBuffer();
          const udpSize = dnsQueryResult.byteLength;
          const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
          if (webSocket.readyState === WS_READY_STATE_OPEN) {
            log(`DNS-запрос успешен, длина сообщения: ${udpSize}`);
            if (iscloudflareHeaderSent) {
              webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
            } else {
              webSocket.send(await new Blob([cloudflareResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
              iscloudflareHeaderSent = true;
            }
          }
        },
      })
    )
    .catch((error) => {
      log("Ошибка UDP DNS: " + error);
    });

  const writer = transformStream.writable.getWriter();

  return {
    /**
     * @param {Uint8Array} chunk
     */
    write(chunk) {
      writer.write(chunk);
    },
  };
}

/**
 * Генерирует конфигурацию VLESS.
 * @param {string} userID Идентификатор пользователя.
 * @param {string | null} hostName Имя хоста.
 * @returns {string} HTML-конфигурация.
 */
function getVlessConfig(userID, hostName) {
  const wVlessws = `\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${CDNIP}:8880?encryption=none&security=none&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#${hostName}`;
  const pVlesswstls = `\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${CDNIP}:8443?encryption=none&security=tls&type=ws&host=${hostName}&sni=${hostName}&fp=random&path=%2F%3Fed%3D2560#${hostName}`;
  const note = `Блог: https://ygkkk.blogspot.com\nYouTube-канал: https://www.youtube.com/@ygkkk\nTelegram-группа: https://t.me/ygkkktg\nTelegram-канал: https://t.me/ygkkktgpd\n\nProxyIP работает глобально: ${proxyIP}:${proxyPort}`;
  const ty = `https://${hostName}/${userID}/ty`;
  const cl = `https://${hostName}/${userID}/cl`;
  const sb = `https://${hostName}/${userID}/sb`;
  const pty = `https://${hostName}/${userID}/pty`;
  const pcl = `https://${hostName}/${userID}/pcl`;
  const psb = `https://${hostName}/${userID}/psb`;

  const wkVlessshare = btoa(`\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP1}:${PT1}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V1_${IP1}_${PT1}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP2}:${PT2}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V2_${IP2}_${PT2}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP3}:${PT3}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V3_${IP3}_${PT3}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP4}:${PT4}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V4_${IP4}_${PT4}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP5}:${PT5}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V5_${IP5}_${PT5}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP6}:${PT6}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V6_${IP6}_${PT6}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP7}:${PT7}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V7_${IP7}_${PT7}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`);

  const pgVlessshare = btoa(`\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`);

  const noteshow = note.replace(/\n/g, '<br>');
  const displayHtml = `
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz" crossorigin="anonymous"></script>
<style>
.limited-width {
    max-width: 200px;
    overflow: auto;
    word-wrap: break-word;
}
</style>
</head>
<script>
function copyToClipboard(text) {
  const input = document.createElement('textarea');
  input.style.position = 'fixed';
  input.style.opacity = 0;
  input.value = text;
  document.body.appendChild(input);
  input.select();
  document.execCommand('Copy');
  document.body.removeChild(input);
  alert('Скопировано в буфер обмена');
}
</script>
`;
  if (hostName.includes("workers.dev")) {
    return `
<br>
<br>
${displayHtml}
<body>
<div class="container">
    <div class="row">
        <div class="col-md-12">
            <h1>Скрипт прокси Cloudflare-workers/pages-VLESS V25.5.4</h1>
            <hr>
            <p>${noteshow}</p>
            <hr>
            <hr>
            <hr>
            <br>
            <br>
            <h3>1: Узел CF-workers-VLESS+ws</h3>
            <table class="table">
                <thead>
                    <tr>
                        <th>Особенности узла:</th>
                        <th>Ссылка на узел:</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">TLS-шифрование отключено, игнорирует блокировку доменов</td>
                        <td class="limited-width">${wVlessws}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${wVlessws}')">Скопировать ссылку</button></td>
                    </tr>
                </tbody>
            </table>
            <h5>Параметры клиента:</h5>
            <ul>
                <li>Адрес клиента (address): пользовательский домен, предпочтительный домен, предпочтительный IP или IP обратного прокси</li>
                <li>Порт (port): выберите один из 7 HTTP-портов (80, 8080, 8880, 2052, 2082, 2086, 2095) или порт IP обратного прокси</li>
                <li>Идентификатор пользователя (uuid): ${userID}</li>
                <li>Протокол передачи (network): ws или websocket</li>
                <li>Маскировочный домен (host): ${hostName}</li>
                <li>Путь (path): /?ed=2560</li>
                <li>Безопасность передачи (TLS): отключена</li>
            </ul>
            <hr>
            <hr>
            <hr>
            <br>
            <br>
            <h3>2: Узел CF-workers-VLESS+ws+tls</h3>
            <table class="table">
                <thead>
                    <tr>
                        <th>Особенности узла:</th>
                        <th>Ссылка на узел:</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">TLS-шифрование включено, <br>если клиент поддерживает функцию фрагментации (Fragment), рекомендуется включить для предотвращения блокировки доменов</td>
                        <td class="limited-width">${pVlesswstls}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${pVlesswstls}')">Скопировать ссылку</button></td>
                    </tr>
                </tbody>
            </table>
            <h5>Параметры клиента:</h5>
            <ul>
                <li>Адрес клиента (address): пользовательский домен, предпочтительный домен, предпочтительный IP или IP обратного прокси</li>
                <li>Порт (port): выберите один из 6 HTTPS-портов (443, 8443, 2053, 2083, 2087, 2096) или порт IP обратного прокси</li>
                <li>Идентификатор пользователя (uuid): ${userID}</li>
                <li>Протокол передачи (network): ws или websocket</li>
                <li>Маскировочный домен (host): ${hostName}</li>
                <li>Путь (path): /?ed=2560</li>
                <li>Безопасность передачи (TLS): включена</li>
                <li>Пропуск проверки сертификата (allowInsecure): false</li>
            </ul>
            <hr>
            <hr>
            <hr>
            <br>
            <br>
            <h3>3: Ссылки на подписки для универсального использования, Clash-meta и Sing-box:</h3>
            <hr>
            <p>Примечание:<br>1. По умолчанию каждая ссылка на подписку включает 13 портов (TLS и без TLS)<br>2. Текущий домен workers используется для подписки, обновление требует прокси<br>3. Если клиент не поддерживает фрагментацию, узлы с TLS недоступны</p>
            <hr>
            <table class="table">
                <thead>
                    <tr>
                        <th>Универсальная ссылка для общего использования (можно импортировать в клиент):</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${wkVlessshare}')">Скопировать ссылку</button></td>
                    </tr>
                </tbody>
            </table>
            <table class="table">
                <thead>
                    <tr>
                        <th>Универсальная ссылка на подписку:</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">${ty}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${ty}')">Скопировать ссылку</button></td>
                    </tr>
                </tbody>
            </table>
            <table class="table">
                <thead>
                    <tr>
                        <th>Ссылка на подписку Clash-meta:</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">${cl}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${cl}')">Скопировать ссылку</button></td>
                    </tr>
                </tbody>
            </table>
            <table class="table">
                <thead>
                    <tr>
                        <th>Ссылка на подписку Sing-box:</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">${sb}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${sb}')">Скопировать ссылку</button></td>
                    </tr>
                </tbody>
            </table>
            <br>
            <br>
        </div>
    </div>
</div>
</body>
`;
  } else {
    return `
<br>
<br>
${displayHtml}
<body>
<div class="container">
    <div class="row">
        <div class="col-md-12">
            <h1>Скрипт прокси Cloudflare-workers/pages-VLESS V25.5.4</h1>
            <hr>
            <p>${noteshow}</p>
            <hr>
            <hr>
            <hr>
            <br>
            <br>
            <h3>1: Узел CF-pages/workers/пользовательский домен-VLESS+ws+tls</h3>
            <table class="table">
                <thead>
                    <tr>
                        <th>Особенности узла:</th>
                        <th>Ссылка на узел:</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">TLS-шифрование включено, <br>если клиент поддерживает функцию фрагментации (Fragment), можно включить для предотвращения блокировки доменов</td>
                        <td class="limited-width">${pVlesswstls}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${pVlesswstls}')">Скопировать ссылку</button></td>
                    </tr>
                </tbody>
            </table>
            <h5>Параметры клиента:</h5>
            <ul>
                <li>Адрес клиента (address): пользовательский домен, предпочтительный домен, предпочтительный IP или IP обратного прокси</li>
                <li>Порт (port): выберите один из 6 HTTPS-портов (443, 8443, 2053, 2083, 2087, 2096) или порт IP обратного прокси</li>
                <li>Идентификатор пользователя (uuid): ${userID}</li>
                <li>Протокол передачи (network): ws или websocket</li>
                <li>Маскировочный домен (host): ${hostName}</li>
                <li>Путь (path): /?ed=2560</li>
                <li>Безопасность передачи (TLS): включена</li>
                <li>Пропуск проверки сертификата (allowInsecure): false</li>
            </ul>
            <hr>
            <hr>
            <hr>
            <br>
            <br>
            <h3>2: Ссылки на подписки для универсального использования, Clash-meta и Sing-box:</h3>
            <hr>
            <p>Примечание: следующие ссылки на подписку содержат только 6 портов TLS</p>
            <hr>
            <table class="table">
                <thead>
                    <tr>
                        <th>Универсальная ссылка для общего использования (можно импортировать в клиент):</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${pgVlessshare}')">Скопировать ссылку</button></td>
                    </tr>
                </tbody>
            </table>
            <table class="table">
                <thead>
                    <tr>
                        <th>Универсальная ссылка на подписку:</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">${pty}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${pty}')">Скопировать ссылку</button></td>
                    </tr>
                </tbody>
            </table>
            <table class="table">
                <thead>
                    <tr>
                        <th>Ссылка на подписку Clash-meta:</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">${pcl}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${pcl}')">Скопировать ссылку</button></td>
                    </tr>
                </tbody>
            </table>
            <table Periodicals="table">
                <thead>
                    <tr>
                        <th>Ссылка на подписку Sing-box:</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td class="limited-width">${psb}</td>
                        <td><button class="btn btn-primary" onclick="copyToClipboard('${psb}')">Скопировать ссылку</button></td>
                    </tr>
                </tbody>
            </table>
            <br>
            <br>
        </div>
    </div>
</div>
</body>
`;
  }
}

function gettyConfig(userID, hostName) {
  const vlessshare = btoa(`\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP1}:${PT1}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V1_${IP1}_${PT1}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP2}:${PT2}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V2_${IP2}_${PT2}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP3}:${PT3}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V3_${IP3}_${PT3}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP4}:${PT4}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V4_${IP4}_${PT4}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP5}:${PT5}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V5_${IP5}_${PT5}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP6}:${PT6}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V6_${IP6}_${PT6}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP7}:${PT7}?encryption=none&security=none&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V7_${IP7}_${PT7}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`);
  return `${vlessshare}`;
}

function getclConfig(userID, hostName) {
  return `
port: 7890
allow-lan: true
mode: rule
log-level: info
unified-delay: true
global-client-fingerprint: chrome
dns:
  enable: false
  listen: :53
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver: 
    - 223.5.5.5
    - 114.114.114.114
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

proxies:
- name: CF_V1_${IP1}_${PT1}
  type: vless
  server: ${IP1.replace(/[\[\]]/g, '')}
  port: ${PT1}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V2_${IP2}_${PT2}
  type: vless
  server: ${IP2.replace(/[\[\]]/g, '')}
  port: ${PT2}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V3_${IP3}_${PT3}
  type: vless
  server: ${IP3.replace(/[\[\]]/g, '')}
  port: ${PT3}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V4_${IP4}_${PT4}
  type: vless
  server: ${IP4.replace(/[\[\]]/g, '')}
  port: ${PT4}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V5_${IP5}_${PT5}
  type: vless
  server: ${IP5.replace(/[\[\]]/g, '')}
  port: ${PT5}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V6_${IP6}_${PT6}
  type: vless
  server: ${IP6.replace(/[\[\]]/g, '')}
  port: ${PT6}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V7_${IP7}_${PT7}
  type: vless
  server: ${IP7.replace(/[\[\]]/g, '')}
  port: ${PT7}
  uuid: ${userID}
  udp: false
  tls: false
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V8_${IP8}_${PT8}
  type: vless
  server: ${IP8.replace(/[\[\]]/g, '')}
  port: ${PT8}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V9_${IP9}_${PT9}
  type: vless
  server: ${IP9.replace(/[\[\]]/g, '')}
  port: ${PT9}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V10_${IP10}_${PT10}
  type: vless
  server: ${IP10.replace(/[\[\]]/g, '')}
  port: ${PT10}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V11_${IP11}_${PT11}
  type: vless
  server: ${IP11.replace(/[\[\]]/g, '')}
  port: ${PT11}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V12_${IP12}_${PT12}
  type: vless
  server: ${IP12.replace(/[\[\]]/g, '')}
  port: ${PT12}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V13_${IP13}_${PT13}
  type: vless
  server: ${IP13.replace(/[\[\]]/g, '')}
  port: ${PT13}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

proxy-groups:
- name: Балансировка нагрузки
  type: load-balance
  url: http://www.gstatic.com/generate_204
  interval: 300
  proxies:
    - CF_V1_${IP1}_${PT1}
    - CF_V2_${IP2}_${PT2}
    - CF_V3_${IP3}_${PT3}
    - CF_V4_${IP4}_${PT4}
    - CF_V5_${IP5}_${PT5}
    - CF_V6_${IP6}_${PT6}
    - CF_V7_${IP7}_${PT7}
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

- name: Автоматический выбор
  type: url-test
  url: http://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  proxies:
    - CF_V1_${IP1}_${PT1}
    - CF_V2_${IP2}_${PT2}
    - CF_V3_${IP3}_${PT3}
    - CF_V4_${IP4}_${PT4}
    - CF_V5_${IP5}_${PT5}
    - CF_V6_${IP6}_${PT6}
    - CF_V7_${IP7}_${PT7}
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

- name: 🌍 Выбор прокси
  type: select
  proxies:
    - Балансировка нагрузки
    - Автоматический выбор
    - DIRECT
    - CF_V1_${IP1}_${PT1}
    - CF_V2_${IP2}_${PT2}
    - CF_V3_${IP3}_${PT3}
    - CF_V4_${IP4}_${PT4}
    - CF_V5_${IP5}_${PT5}
    - CF_V6_${IP6}_${PT6}
    - CF_V7_${IP7}_${PT7}
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🌍 Выбор прокси`;
}

function getsbConfig(userID, hostName) {
  return `{
      "log": {
        "disabled": false,
        "level": "info",
        "timestamp": true
      },
      "experimental": {
        "clash_api": {
          "external_controller": "127.0.0.1:9090",
          "external_ui": "ui",
          "external_ui_download_url": "",
          "external_ui_download_detour": "",
          "secret": "",
          "default_mode": "Rule"
        },
        "cache_file": {
          "enabled": true,
          "path": "cache.db",
          "store_fakeip": true
        }
      },
      "dns": {
        "servers": [
          {
            "tag": "proxydns",
            "address": "tls://8.8.8.8/dns-query",
            "detour": "select"
          },
          {
            "tag": "localdns",
            "address": "h3://223.5.5.5/dns-query",
            "detour": "direct"
          },
          {
            "tag": "dns_fakeip",
            "address": "fakeip"
          }
        ],
        "rules": [
          {
            "outbound": "any",
            "server": "localdns",
            "disable_cache": true
          },
          {
            "clash_mode": "Global",
            "server": "proxydns"
          },
          {
            "clash_mode": "Direct",
            "server": "localdns"
          },
          {
            "rule_set": "geosite-cn",
            "server": "localdns"
          },
          {
            "rule_set": "geosite-geolocation-!cn",
            "server": "proxydns"
          },
          {
            "rule_set": "geosite-geolocation-!cn",
            "query_type": [
              "A",
              "AAAA"
            ],
            "server": "dns_fakeip"
          }
        ],
        "fakeip": {
          "enabled": true,
          "inet4_range": "198.18.0.0/15",
          "inet6_range": "fc00::/18"
        },
        "independent_cache": true,
        "final": "proxydns"
      },
      "inbounds": [
        {
          "type": "tun",
          "tag": "tun-in",
          "address": [
            "172.19.0.1/30",
            "fd00::1/126"
          ],
          "auto_route": true,
          "strict_route": true,
          "sniff": true,
          "sniff_override_destination": true,
          "domain_strategy": "prefer_ipv4"
        }
      ],
      "outbounds": [
        {
          "tag": "select",
          "type": "selector",
          "default": "auto",
          "outbounds": [
            "auto",
            "CF_V1_${IP1}_${PT1}",
            "CF_V2_${IP2}_${PT2}",
            "CF_V3_${IP3}_${PT3}",
            "CF_V4_${IP4}_${PT4}",
            "CF_V5_${IP5}_${PT5}",
            "CF_V6_${IP6}_${PT6}",
            "CF_V7_${IP7}_${PT7}",
            "CF_V8_${IP8}_${PT8}",
            "CF_V9_${IP9}_${PT9}",
            "CF_V10_${IP10}_${PT10}",
            "CF_V11_${IP11}_${PT11}",
            "CF_V12_${IP12}_${PT12}",
            "CF_V13_${IP13}_${PT13}",
            "direct"
          ]
        },
        {
          "tag": "auto",
          "type": "urltest",
          "outbounds": [
            "CF_V1_${IP1}_${PT1}",
            "CF_V2_${IP2}_${PT2}",
            "CF_V3_${IP3}_${PT3}",
            "CF_V4_${IP4}_${PT4}",
            "CF_V5_${IP5}_${PT5}",
            "CF_V6_${IP6}_${PT6}",
            "CF_V7_${IP7}_${PT7}",
            "CF_V8_${IP8}_${PT8}",
            "CF_V9_${IP9}_${PT9}",
            "CF_V10_${IP10}_${PT10}",
            "CF_V11_${IP11}_${PT11}",
            "CF_V12_${IP12}_${PT12}",
            "CF_V13_${IP13}_${PT13}"
          ],
          "url": "http://www.gstatic.com/generate_204",
          "interval": "5m",
          "tolerance": 50
        },
        {
          "tag": "direct",
          "type": "direct"
        },
        {
          "tag": "CF_V1_${IP1}_${PT1}",
          "type": "vless",
          "server": "${IP1.replace(/[\[\]]/g, '')}",
          "server_port": ${PT1},
          "uuid": "${userID}",
          "packet_encoding": "",
          "transport": {
            "type": "ws",
            "path": "/?ed=2560",
            "headers": {
              "Host": "${hostName}"
            },
            "early_data_header_name": "Sec-WebSocket-Protocol"
          }
        },
        {
          "tag": "CF_V2_${IP2}_${PT2}",
          "type": "vless",
          "server": "${IP2.replace(/[\[\]]/g, '')}",
          "server_port": ${PT2},
          "uuid": "${userID}",
          "packet_encoding": "",
          "transport": {
            "type": "ws",
            "path": "/?ed=2560",
            "headers": {
              "Host": "${hostName}"
            },
            "early_data_header_name": "Sec-WebSocket-Protocol"
          }
        },
        {
          "tag": "CF_V3_${IP3}_${PT3}",
          "type": "vless",
          "server": "${IP3.replace(/[\[\]]/g, '')}",
          "server_port": ${PT3},
          "uuid": "${userID}",
          "packet_encoding": "",
          "transport": {
            "type": "ws",
            "path": "/?ed=2560",
            "headers": {
              "Host": "${hostName}"
            },
            "early_data_header_name": "Sec-WebSocket-Protocol"
          }
        },
        {
          "tag": "CF_V4_${IP4}_${PT4}",
          "type": "vless",
          "server": "${IP4.replace(/[\[\]]/g, '')}",
          "server_port": ${PT4},
          "uuid": "${userID}",
          "packet_encoding": "",
          "transport": {
            "type": "ws",
            "path": "/?ed=2560",
            "headers": {
              "Host": "${hostName}"
            },
            "early_data_header_name": "Sec-WebSocket-Protocol"
          }
        },
        {
          "tag": "CF_V5_${IP5}_${PT5}",
          "type": "vless",
          "server": "${IP5.replace(/[\[\]]/g, '')}",
          "server_port": ${PT5},
          "uuid": "${userID}",
          "packet_encoding": "",
          "transport": {
            "type": "ws",
            "path": "/?ed=2560",
            "headers": {
              "Host": "${hostName}"
            },
            "early_data_header_name": "Sec-WebSocket-Protocol"
          }
        },
        {
          "tag": "CF_V6_${IP6}_${PT6}",
          "type": "vless",
          "server": "${IP6.replace(/[\[\]]/g, '')}",
          "server_port": ${PT6},
          "uuid": "${userID}",
          "packet_encoding": "",
          "transport": {
            "type": "ws",
            "path": "/?ed=2560",
            "headers": {
              "Host": "${hostName}"
            },
            "early_data_header_name": "Sec-WebSocket-Protocol"
          }
        },
        {
          "tag": "CF_V7_${IP7}_${PT7}",
          "type": "vless",
          "server": "${IP7.replace(/[\[\]]/g, '')}",
          "server_port": ${PT7},
          "uuid": "${userID}",
          "packet_encoding": "",
          "transport": {
            "type": "ws",
            "path": "/?ed=2560",
            "headers": {
              "Host": "${hostName}"
            },
            "early_data_header_name": "Sec-WebSocket-Protocol"
          }
        },
        {
          "tag": "CF_V8_${IP8}_${PT8}",
          "type": "vless",
          "server": "${IP8.replace(/[\[\]]/g, '')}",
          "server_port": ${PT8},
          "uuid": "${userID}",
          "tls": {
            "enabled": true,
            "server_name": "${hostName}"
          },
          "packet_encoding": "",
          "transport": {
            "type": "ws",
            "path": "/?ed=2560",
            "headers": {
              "Host": "${hostName}"
            },
            "early_data_header_name": "Sec-WebSocket-Protocol"
          }
        },
        {
          "tag": "CF_V9_${IP9}_${PT9}",
          "type": "vless",
          "server": "${IP9.replace(/[\[\]]/g, '')}",
          "server_port": ${PT9},
          "uuid": "${userID}",
          "tls": {
            "enabled": true,
            "server_name": "${hostName}"
          },
          "packet_encoding": "",
          "transport": {
            "type": "ws",
            "path": "/?ed=2560",
            "headers": {
              "Host": "${hostName}"
            },
            "early_data_header_name": "Sec-WebSocket-Protocol"
          }
        },
        {
          "tag": "CF_V10_${IP10}_${PT10}",
          "type": "vless",
          "server": "${IP10.replace(/[\[\]]/g, '')}",
          "server_port": ${PT10},
          "uuid": "${userID}",
          "tls": {
            "enabled": true,
            "server_name": "${hostName}"
          },
          "packet_encoding": "",
          "transport": {
            "type": "ws",
            "path": "/?ed=2560",
            "headers": {
              "Host": "${hostName}"
            },
            "early_data_header_name": "Sec-WebSocket-Protocol"
          }
        },
        {
          "tag": "CF_V11_${IP11}_${PT11}",
          "type": "vless",
          "server": "${IP11.replace(/[\[\]]/g, '')}",
          "server_port": ${PT11},
          "uuid": "${userID}",
          "tls": {
            "enabled": true,
            "server_name": "${hostName}"
          },
          "packet_encoding": "",
          "transport": {
            "type": "ws",
            "path": "/?ed=2560",
            "headers": {
              "Host": "${hostName}"
            },
            "early_data_header_name": "Sec-WebSocket-Protocol"
          }
        },
        {
          "tag": "CF_V12_${IP12}_${PT12}",
          "type": "vless",
          "server": "${IP12.replace(/[\[\]]/g, '')}",
          "server_port": ${PT12},
          "uuid": "${userID}",
          "tls": {
            "enabled": true,
            "server_name": "${hostName}"
          },
          "packet_encoding": "",
          "transport": {
            "type": "ws",
            "path": "/?ed=2560",
            "headers": {
              "Host": "${hostName}"
            },
            "early_data_header_name": "Sec-WebSocket-Protocol"
          }
        },
        {
          "tag": "CF_V13_${IP13}_${PT13}",
          "type": "vless",
          "server": "${IP13.replace(/[\[\]]/g, '')}",
          "server_port": ${PT13},
          "uuid": "${userID}",
          "tls": {
            "enabled": true,
            "server_name": "${hostName}"
          },
          "packet_encoding": "",
          "transport": {
            "type": "ws",
            "path": "/?ed=2560",
            "headers": {
              "Host": "${hostName}"
            },
            "early_data_header_name": "Sec-WebSocket-Protocol"
          }
        }
      ],
      "route": {
        "rules": [
          {
            "rule_set": [
              "geoip-cn",
              "geosite-cn"
            ],
            "outbound": "direct"
          },
          {
            "rule_set": "geosite-geolocation-!cn",
            "outbound": "select"
          }
        ],
        "rule_set": [
          {
            "tag": "geoip-cn",
            "type": "remote",
            "format": "binary",
            "url": "https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip-cn.srs",
            "download_detour": "select"
          },
          {
            "tag": "geosite-cn",
            "type": "remote",
            "format": "binary",
            "url": "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite-cn.srs",
            "download_detour": "select"
          },
          {
            "tag": "geosite-geolocation-!cn",
            "type": "remote",
            "format": "binary",
            "url": "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite-geolocation-!cn.srs",
            "download_detour": "select"
          }
        ],
        "final": "select"
      }
    }`;
}

/**
 * Генерирует универсальную конфигурацию подписки (TLS-only).
 * @param {string} userID Идентификатор пользователя.
 * @param {string | null} hostName Имя хоста.
 * @returns {string} Конфигурация в формате base64.
 */
function getptyConfig(userID, hostName) {
  const vlessshare = btoa(`\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP8}:${PT8}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V8_${IP8}_${PT8}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP9}:${PT9}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V9_${IP9}_${PT9}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP10}:${PT10}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V10_${IP10}_${PT10}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP11}:${PT11}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V11_${IP11}_${PT11}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP12}:${PT12}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V12_${IP12}_${PT12}\n\u0076\u006c\u0065\u0073\u0073\u003A//${userID}\u0040${IP13}:${PT13}?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_V13_${IP13}_${PT13}`);
  return `${vlessshare}`;
}

/**
 * Генерирует конфигурацию подписки для Clash-meta (TLS-only).
 * @param {string} userID Идентификатор пользователя.
 * @param {string | null} hostName Имя хоста.
 * @returns {string} Конфигурация в формате YAML.
 */
function getpclConfig(userID, hostName) {
  return `
port: 7890
allow-lan: true
mode: rule
log-level: info
unified-delay: true
global-client-fingerprint: chrome
dns:
  enable: false
  listen: :53
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver: 
    - 223.5.5.5
    - 114.114.114.114
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

proxies:
- name: CF_V8_${IP8}_${PT8}
  type: vless
  server: ${IP8.replace(/[\[\]]/g, '')}
  port: ${PT8}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V9_${IP9}_${PT9}
  type: vless
  server: ${IP9.replace(/[\[\]]/g, '')}
  port: ${PT9}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V10_${IP10}_${PT10}
  type: vless
  server: ${IP10.replace(/[\[\]]/g, '')}
  port: ${PT10}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V11_${IP11}_${PT11}
  type: vless
  server: ${IP11.replace(/[\[\]]/g, '')}
  port: ${PT11}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V12_${IP12}_${PT12}
  type: vless
  server: ${IP12.replace(/[\[\]]/g, '')}
  port: ${PT12}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

- name: CF_V13_${IP13}_${PT13}
  type: vless
  server: ${IP13.replace(/[\[\]]/g, '')}
  port: ${PT13}
  uuid: ${userID}
  udp: false
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

proxy-groups:
- name: Балансировка нагрузки
  type: load-balance
  url: http://www.gstatic.com/generate_204
  interval: 300
  proxies:
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

- name: Автоматический выбор
  type: url-test
  url: http://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  proxies:
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

- name: 🌍 Выбор прокси
  type: select
  proxies:
    - Балансировка нагрузки
    - Автоматический выбор
    - DIRECT
    - CF_V8_${IP8}_${PT8}
    - CF_V9_${IP9}_${PT9}
    - CF_V10_${IP10}_${PT10}
    - CF_V11_${IP11}_${PT11}
    - CF_V12_${IP12}_${PT12}
    - CF_V13_${IP13}_${PT13}

rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🌍 Выбор прокси`;
}

/**
 * Генерирует конфигурацию подписки для Sing-box (TLS-only).
 * @param {string} userID Идентификатор пользователя.
 * @param {string | null} hostName Имя хоста.
 * @returns {string} Конфигурация в формате JSON.
 */
function getpsbConfig(userID, hostName) {
  return `{
      "log": {
        "disabled": false,
        "level": "info",
        "timestamp": true
      },
      "experimental": {
        "clash_api": {
          "external_controller": "127.0.0.1:9090",
          "external_ui": "ui",
          "external_ui_download_url": "",
          "external_ui_download_detour": "",
          "secret": "",
          "default_mode": "Rule"
        },
        "cache_file": {
          "enabled": true,
          "path": "cache.db",
          "store_fakeip": true
        }
      },
      "dns": {
        "servers": [
          {
            "tag": "proxydns",
            "address": "tls://8.8.8.8/dns-query",
            "detour": "select"
          },
          {
            "tag": "localdns",
            "address": "h3://223.5.5.5/dns-query",
            "detour": "direct"
          },
          {
            "tag": "dns_fakeip",
            "address": "fakeip"
          }
        ],
        "rules": [
          {
            "outbound": "any",
            "server": "localdns",
            "disable_cache": true
          },
          {
            "clash_mode": "Global",
            "server": "proxydns"
          },
          {
            "clash_mode": "Direct",
            "server": "localdns"
          },
          {
            "rule_set": "geosite-cn",
            "server": "localdns"
          },
          {
            "rule_set": "geosite-geolocation-!cn",
            "server": "proxydns"
          },
          {
            "rule_set": "geosite-geolocation-!cn",
            "query_type": [
              "A",
              "AAAA"
            ],
            "server": "dns_fakeip"
          }
        ],
        "fakeip": {
          "enabled": true,
          "inet4_range": "198.18.0.0/15",
          "inet6_range": "fc00::/18"
        },
        "independent_cache": true,
        "final": "proxydns"
      },
      "inbounds": [
        {
          "type": "tun",
          "tag": "tun-in",
          "address": [
            "172.19.0.1/30",
            "fd00::1/126"
          ],
          "auto_route": true,
          "strict_route": true,
          "sniff": true,
          "sniff_override_destination": true,
          "domain_strategy": "prefer_ipv4"
        }
      ],
      "outbounds": [
        {
          "tag": "select",
          "type": "selector",
          "default": "auto",
          "outbounds": [
            "auto",
            "CF_V8_${IP8}_${PT8}",
            "CF_V9_${IP9}_${PT9}",
            "CF_V10_${IP10}_${PT10}",
            "CF_V11_${IP11}_${PT11}",
            "CF_V12_${IP12}_${PT12}",
            "CF_V13_${IP13}_${PT13}",
            "direct"
          ]
        },
        {
          "tag": "auto",
          "type": "urltest",
          "outbounds": [
            "CF_V8_${IP8}_${PT8}",
            "CF_V9_${IP9}_${PT9}",
            "CF_V10_${IP10}_${PT10}",
            "CF_V11_${IP11}_${PT11}",
            "CF_V12_${IP12}_${PT12}",
            "CF_V13_${IP13}_${PT13}"
          ],
          "url": "http://www.gstatic.com/generate_204",
          "interval": "5m",
          "tolerance": 50
        },
        {
          "tag": "direct",
          "type": "direct"
        },
        {
          "tag": "CF_V8_${IP8}_${PT8}",
          "type": "vless",
          "server": "${IP8.replace(/[\[\]]/g, '')}",
          "server_port": ${PT8},
          "uuid": "${userID}",
          "tls": {
            "enabled": true,
            "server_name": "${hostName}"
          },
          "packet_encoding": "",
          "transport": {
            "type": "ws",
            "path": "/?ed=2560",
            "headers": {
              "Host": "${hostName}"
            },
            "early_data_header_name": "Sec-WebSocket-Protocol"
          }
        },
        {
          "tag": "CF_V9_${IP9}_${PT9}",
          "type": "vless",
          "server": "${IP9.replace(/[\[\]]/g, '')}",
          "server_port": ${PT9},
          "uuid": "${userID}",
          "tls": {
            "enabled": true,
            "server_name": "${hostName}"
          },
          "packet_encoding": "",
          "transport": {
            "type": "ws",
            "path": "/?ed=2560",
            "headers": {
              "Host": "${hostName}"
            },
            "early_data_header_name": "Sec-WebSocket-Protocol"
          }
        },
        {
          "tag": "CF_V10_${IP10}_${PT10}",
          "type": "vless",
          "server": "${IP10.replace(/[\[\]]/g, '')}",
          "server_port": ${PT10},
          "uuid": "${userID}",
          "tls": {
            "enabled": true,
            "server_name": "${hostName}"
          },
          "packet_encoding": "",
          "transport": {
            "type": "ws",
            "path": "/?ed=2560",
            "headers": {
              "Host": "${hostName}"
            },
            "early_data_header_name": "Sec-WebSocket-Protocol"
          }
        },
        {
          "tag": "CF_V11_${IP11}_${PT11}",
          "type": "vless",
          "server": "${IP11.replace(/[\[\]]/g, '')}",
          "server_port": ${PT11},
          "uuid": "${userID}",
          "tls": {
            "enabled": true,
            "server_name": "${hostName}"
          },
          "packet_encoding": "",
          "transport": {
            "type": "ws",
            "path": "/?ed=2560",
            "headers": {
              "Host": "${hostName}"
            },
            "early_data_header_name": "Sec-WebSocket-Protocol"
          }
        },
        {
          "tag": "CF_V12_${IP12}_${PT12}",
          "type": "vless",
          "server": "${IP12.replace(/[\[\]]/g, '')}",
          "server_port": ${PT12},
          "uuid": "${userID}",
          "tls": {
            "enabled": true,
            "server_name": "${hostName}"
          },
          "packet_encoding": "",
          "transport": {
            "type": "ws",
            "path": "/?ed=2560",
            "headers": {
              "Host": "${hostName}"
            },
            "early_data_header_name": "Sec-WebSocket-Protocol"
          }
        },
        {
          "tag": "CF_V13_${IP13}_${PT13}",
          "type": "vless",
          "server": "${IP13.replace(/[\[\]]/g, '')}",
          "server_port": ${PT13},
          "uuid": "${userID}",
          "tls": {
            "enabled": true,
            "server_name": "${hostName}"
          },
          "packet_encoding": "",
          "transport": {
            "type": "ws",
            "path": "/?ed=2560",
            "headers": {
              "Host": "${hostName}"
            },
            "early_data_header_name": "Sec-WebSocket-Protocol"
          }
        }
      ],
      "route": {
        "rules": [
          {
            "rule_set": [
              "geoip-cn",
              "geosite-cn"
            ],
            "outbound": "direct"
          },
          {
            "rule_set": "geosite-geolocation-!cn",
            "outbound": "select"
          }
        ],
        "rule_set": [
          {
            "tag": "geoip-cn",
            "type": "remote",
            "format": "binary",
            "url": "https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip-cn.srs",
            "download_detour": "select"
          },
          {
            "tag": "geosite-cn",
            "type": "remote",
            "format": "binary",
            "url": "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite-cn.srs",
            "download_detour": "select"
          },
          {
            "tag": "geosite-geolocation-!cn",
            "type": "remote",
            "format": "binary",
            "url": "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite-geolocation-!cn.srs",
            "download_detour": "select"
          }
        ],
        "final": "select"
      }
    }`;
}
