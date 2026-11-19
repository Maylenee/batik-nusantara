
import { createRequire as __createRequire } from 'module';
import { fileURLToPath as __fileURLToPath } from 'url';
import { dirname as __pathDirname } from 'path';

// Global variables
const __filename = __fileURLToPath(import.meta.url);
const __dirname = __pathDirname(__filename);
const require = __createRequire(import.meta.url);

// Global require function
globalThis.require = require;
globalThis.__filename = __filename;
globalThis.__dirname = __dirname;

// Dynamic require handler
globalThis.__dynamicRequire = function(id) {
  try {
    return require(id);
  } catch (err) {
    if (err.code === 'ERR_REQUIRE_ESM') {
      // If the module is ESM, try using import()
      return import(id);
    }
    throw err;
  }
};

// Fix Buffer
if (typeof Buffer === 'undefined') {
  globalThis.Buffer = require('buffer').Buffer;
}

// Fix process
if (typeof process === 'undefined') {
  globalThis.process = require('process');
}

// Fix util.promisify
if (!Symbol.for('nodejs.util.promisify.custom')) {
  Symbol.for('nodejs.util.promisify.custom');
}



// ===== Outbound Net Hook (Production Mode Only) =====
// Injected by EdgeOne CLI. Do NOT modify.
(function() {
  if (globalThis.__edgeoneNetHooked) return;
  globalThis.__edgeoneNetHooked = true;

  // 灰度总开关：整个 hook 都不安装
  if (process.env.EDGEONE_OUTBOUND_HOOK_DISABLED === '1' ||
      process.env.EDGEONE_OUTBOUND_HOOK_DISABLED === 'true') {
    return;
  }

  const __hookMode = (process.env.EDGEONE_OUTBOUND_HOOK_MODE || 'enforce').toLowerCase();
  // observe 模式：只打日志不拦，用于灰度阶段观察误伤
  const __observeOnly = __hookMode === 'observe';

  const __async_hooks = require('async_hooks');
  const __net = require('net');
  const __tls = require('tls');

  // AsyncLocalStorage 单例：runtime 入口 als.run(store, () => handler(...))
  const __als = new __async_hooks.AsyncLocalStorage();
  globalThis.__edgeoneRestrictedALS = __als;

  // ---------- 白名单构建 ----------
  const __staticSuffixes = [
    '.edgeone.site',
    '.tencentyun.com', // OTLP / 观测 collector 常用域名后缀
  ];
  const __staticHosts = new Set([
    'localhost',
    'ip6-localhost',
    'ip6-loopback',
  ]);

  // 动态白名单：从环境变量读取（OTLP endpoint / 用户显式 bypass）
  function __hostFromEndpoint(v) {
    if (!v) return '';
    try {
      // 兼容 "host:port" 与 "http(s)://host[:port]/path" 两种形式
      const s = String(v).trim();
      if (!s) return '';
      if (s.includes('://')) return new URL(s).hostname;
      return s.split('/')[0].split(':')[0];
    } catch (_) {
      return '';
    }
  }

  const __dynamicHosts = new Set();
  const __otlpHost = __hostFromEndpoint(process.env.EDGEONE_OTLP_ENDPOINT);
  if (__otlpHost) __dynamicHosts.add(__otlpHost);

  const __bypassRaw = process.env.EDGEONE_OUTBOUND_BYPASS_HOSTS || '';
  if (__bypassRaw) {
    for (const item of __bypassRaw.split(',')) {
      const h = item.trim();
      if (h) __dynamicHosts.add(h);
    }
  }

  // IPv4 私网 / 回环判定（127.0.0.0/8, ::1）
  function __isLoopbackOrPrivate(host) {
    if (!host || typeof host !== 'string') return false;
    // IPv6 loopback
    if (host === '::1' || host === '[::1]') return true;
    // IPv4 loopback 127.x.x.x
    if (/^127\./.test(host)) return true;
    // 明确不拦 Unix socket path（host 为空、路径含斜杠场景由调用方保证）
    return false;
  }

  function __isWhitelisted(host) {
    if (!host) return true; // Unix socket / undefined host：放行，交给上层
    const h = String(host).toLowerCase();
    if (__staticHosts.has(h)) return true;
    if (__dynamicHosts.has(h)) return true;
    for (const suffix of __staticSuffixes) {
      if (h.endsWith(suffix)) return true;
    }
    if (__isLoopbackOrPrivate(h)) return true;
    return false;
  }

  function __currentRequestId() {
    try {
      const store = __als.getStore();
      return (store && store.requestId) || '';
    } catch (_) { return ''; }
  }

  function __isRestricted() {
    try {
      const store = __als.getStore();
      return !!(store && store.restricted === true);
    } catch (_) { return false; }
  }

  function __buildError(host, port) {
    const rid = __currentRequestId();
    const err = new Error('PagesLimit: egress quota may have been exceeded');
    err.code = 'OUTBOUND_RESTRICTED';
    err.host = host;
    err.port = port;
    return err;
  }

  // observe 模式下发一行结构化 stderr 日志
  function __logObserve(kind, host, port) {
    try {
      const rid = __currentRequestId();
      process.stderr.write(
        JSON.stringify({
          type: 'outbound_restricted_observe',
          kind: kind,
          host: host,
          port: port,
          requestId: rid,
          ts: Date.now(),
        }) + '\n'
      );
    } catch (_) {}
  }

  // ---------- 提取 host/port 的兼容逻辑 ----------
  // net.createConnection / net.connect 签名有多态：
  //   (options[, cb])
  //   (port[, host][, cb])
  //   (path[, cb])  // Unix socket
  function __extractHostPort(args) {
    if (args.length === 0) return { host: '', port: 0, isSocket: false };
    const a0 = args[0];
    if (typeof a0 === 'object' && a0 !== null) {
      if (a0.path) return { host: '', port: 0, isSocket: true };
      return {
        host: a0.host || a0.hostname || '',
        port: Number(a0.port) || 0,
        isSocket: false,
      };
    }
    if (typeof a0 === 'string' && !/^\d+$/.test(a0)) {
      // 视为 Unix socket path
      return { host: '', port: 0, isSocket: true };
    }
    // (port[, host][, cb])
    const port = Number(a0) || 0;
    let host = '';
    if (typeof args[1] === 'string') host = args[1];
    return { host: host, port: port, isSocket: false };
  }

  function __checkAndMaybeBlock(kind, host, port, isSocket) {
    if (isSocket) return null;               // Unix socket 一律放行
    if (!__isRestricted()) return null;      // 本请求未标 restricted
    if (__isWhitelisted(host)) return null;  // 命中白名单

    if (__observeOnly) {
      __logObserve(kind, host, port);
      return null;
    }
    return __buildError(host, port);
  }

  // ---------- Hook net.createConnection / net.connect ----------
  const __origCreateConnection = __net.createConnection;
  const __origConnect = __net.connect;

  function __wrappedCreateConnection() {
    const args = Array.from(arguments);
    const { host, port, isSocket } = __extractHostPort(args);
    const err = __checkAndMaybeBlock('net', host, port, isSocket);
    if (err) {
      // 返回一个立即 emit('error') 的 socket，行为对齐 net 原生的异步错误
      const s = new __net.Socket();
      // 找 callback 参数（最后一个是 function 的）以便同步告知
      const cb = typeof args[args.length - 1] === 'function' ? args[args.length - 1] : null;
      process.nextTick(() => {
        s.emit('error', err);
        if (cb) { try { cb(err); } catch (_) {} }
        try { s.destroy(err); } catch (_) {}
      });
      return s;
    }
    return __origCreateConnection.apply(__net, args);
  }

  __net.createConnection = __wrappedCreateConnection;
  __net.connect = __wrappedCreateConnection;

  // ---------- Hook tls.connect ----------
  // TLS 建连时 tls.connect 内部会走一次 socket 建连（可能通过 net.createConnection，
  // 也可能自行创建），这里补一层同层拦截，避免依赖内部实现细节。
  const __origTlsConnect = __tls.connect;
  __tls.connect = function() {
    const args = Array.from(arguments);
    let host = '';
    let port = 0;
    const a0 = args[0];
    if (typeof a0 === 'object' && a0 !== null) {
      host = a0.host || a0.hostname || a0.servername || '';
      port = Number(a0.port) || 0;
    } else if (typeof a0 === 'number' || (typeof a0 === 'string' && /^\d+$/.test(a0))) {
      port = Number(a0) || 0;
      if (typeof args[1] === 'string') host = args[1];
      else if (typeof args[1] === 'object' && args[1] !== null) {
        host = args[1].host || args[1].hostname || args[1].servername || '';
      }
    }
    const err = __checkAndMaybeBlock('tls', host, port, false);
    if (err) {
      const s = new __tls.TLSSocket(new __net.Socket());
      const cb = typeof args[args.length - 1] === 'function' ? args[args.length - 1] : null;
      process.nextTick(() => {
        s.emit('error', err);
        if (cb) { try { cb(err); } catch (_) {} }
        try { s.destroy(err); } catch (_) {}
      });
      return s;
    }
    return __origTlsConnect.apply(__tls, args);
  };
})();



var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __publicField = (obj, key, value) => {
  __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);
  return value;
};
var __accessCheck = (obj, member, msg) => {
  if (!member.has(obj))
    throw TypeError("Cannot " + msg);
};
var __privateGet = (obj, member, getter) => {
  __accessCheck(obj, member, "read from private field");
  return getter ? getter.call(obj) : member.get(obj);
};
var __privateAdd = (obj, member, value) => {
  if (member.has(obj))
    throw TypeError("Cannot add the same private member more than once");
  member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
};
var __privateSet = (obj, member, value, setter) => {
  __accessCheck(obj, member, "write to private field");
  setter ? setter.call(obj, value) : member.set(obj, value);
  return value;
};
var require_stdin = __commonJS({
  "<stdin>"(exports, module) {
    var _e, _t, _a;
    var hs = Object.create;
    var he = Object.defineProperty;
    var us = Object.getOwnPropertyDescriptor;
    var ds = Object.getOwnPropertyNames;
    var ps = Object.getPrototypeOf, gs = Object.prototype.hasOwnProperty;
    var b = (t, e) => () => (e || t((e = { exports: {} }).exports, e), e.exports), _s = (t, e) => {
      for (var s in e)
        he(t, s, { get: e[s], enumerable: true });
    }, Ze = (t, e, s, r) => {
      if (e && typeof e == "object" || typeof e == "function")
        for (let n of ds(e))
          !gs.call(t, n) && n !== s && he(t, n, { get: () => e[n], enumerable: !(r = us(e, n)) || r.enumerable });
      return t;
    };
    var P = (t, e, s) => (s = t != null ? hs(ps(t)) : {}, Ze(e || !t || !t.__esModule ? he(s, "default", { value: t, enumerable: true }) : s, t)), ms = (t) => Ze(he({}, "__esModule", { value: true }), t);
    var N = b((gn, tt) => {
      "use strict";
      var Qe = ["nodebuffer", "arraybuffer", "fragments"], et = typeof Blob < "u";
      et && Qe.push("blob");
      tt.exports = { BINARY_TYPES: Qe, CLOSE_TIMEOUT: 3e4, EMPTY_BUFFER: Buffer.alloc(0), GUID: "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", hasBlob: et, kForOnEventAttribute: Symbol("kIsForOnEventAttribute"), kListener: Symbol("kListener"), kStatusCode: Symbol("status-code"), kWebSocket: Symbol("websocket"), NOOP: () => {
      } };
    });
    var ne = b((_n, ue) => {
      "use strict";
      var { EMPTY_BUFFER: ys } = N(), Pe = Buffer[Symbol.species];
      function Ss(t, e) {
        if (t.length === 0)
          return ys;
        if (t.length === 1)
          return t[0];
        let s = Buffer.allocUnsafe(e), r = 0;
        for (let n = 0; n < t.length; n++) {
          let i = t[n];
          s.set(i, r), r += i.length;
        }
        return r < e ? new Pe(s.buffer, s.byteOffset, r) : s;
      }
      function st(t, e, s, r, n) {
        for (let i = 0; i < n; i++)
          s[r + i] = t[i] ^ e[i & 3];
      }
      function rt(t, e) {
        for (let s = 0; s < t.length; s++)
          t[s] ^= e[s & 3];
      }
      function Es(t) {
        return t.length === t.buffer.byteLength ? t.buffer : t.buffer.slice(t.byteOffset, t.byteOffset + t.length);
      }
      function Ne(t) {
        if (Ne.readOnly = true, Buffer.isBuffer(t))
          return t;
        let e;
        return t instanceof ArrayBuffer ? e = new Pe(t) : ArrayBuffer.isView(t) ? e = new Pe(t.buffer, t.byteOffset, t.byteLength) : (e = Buffer.from(t), Ne.readOnly = false), e;
      }
      ue.exports = { concat: Ss, mask: st, toArrayBuffer: Es, toBuffer: Ne, unmask: rt };
      if (!process.env.WS_NO_BUFFER_UTIL)
        try {
          let t = require("bufferutil");
          ue.exports.mask = function(e, s, r, n, i) {
            i < 48 ? st(e, s, r, n, i) : t.mask(e, s, r, n, i);
          }, ue.exports.unmask = function(e, s) {
            e.length < 32 ? rt(e, s) : t.unmask(e, s);
          };
        } catch {
        }
    });
    var ot = b((mn, it) => {
      "use strict";
      var nt = Symbol("kDone"), Ae = Symbol("kRun"), Be = class {
        constructor(e) {
          this[nt] = () => {
            this.pending--, this[Ae]();
          }, this.concurrency = e || 1 / 0, this.jobs = [], this.pending = 0;
        }
        add(e) {
          this.jobs.push(e), this[Ae]();
        }
        [Ae]() {
          if (this.pending !== this.concurrency && this.jobs.length) {
            let e = this.jobs.shift();
            this.pending++, e(this[nt]);
          }
        }
      };
      it.exports = Be;
    });
    var J = b((yn, ct) => {
      "use strict";
      var ie = require("zlib"), at = ne(), xs = ot(), { kStatusCode: lt } = N(), bs = Buffer[Symbol.species], ws = Buffer.from([0, 0, 255, 255]), pe = Symbol("permessage-deflate"), A = Symbol("total-length"), K = Symbol("callback"), M = Symbol("buffers"), X = Symbol("error"), de, Ie = class {
        constructor(e) {
          if (this._options = e || {}, this._threshold = this._options.threshold !== void 0 ? this._options.threshold : 1024, this._maxPayload = this._options.maxPayload | 0, this._isServer = !!this._options.isServer, this._deflate = null, this._inflate = null, this.params = null, !de) {
            let s = this._options.concurrencyLimit !== void 0 ? this._options.concurrencyLimit : 10;
            de = new xs(s);
          }
        }
        static get extensionName() {
          return "permessage-deflate";
        }
        offer() {
          let e = {};
          return this._options.serverNoContextTakeover && (e.server_no_context_takeover = true), this._options.clientNoContextTakeover && (e.client_no_context_takeover = true), this._options.serverMaxWindowBits && (e.server_max_window_bits = this._options.serverMaxWindowBits), this._options.clientMaxWindowBits ? e.client_max_window_bits = this._options.clientMaxWindowBits : this._options.clientMaxWindowBits == null && (e.client_max_window_bits = true), e;
        }
        accept(e) {
          return e = this.normalizeParams(e), this.params = this._isServer ? this.acceptAsServer(e) : this.acceptAsClient(e), this.params;
        }
        cleanup() {
          if (this._inflate && (this._inflate.close(), this._inflate = null), this._deflate) {
            let e = this._deflate[K];
            this._deflate.close(), this._deflate = null, e && e(new Error("The deflate stream was closed while data was being processed"));
          }
        }
        acceptAsServer(e) {
          let s = this._options, r = e.find((n) => !(s.serverNoContextTakeover === false && n.server_no_context_takeover || n.server_max_window_bits && (s.serverMaxWindowBits === false || typeof s.serverMaxWindowBits == "number" && s.serverMaxWindowBits > n.server_max_window_bits) || typeof s.clientMaxWindowBits == "number" && (typeof n.client_max_window_bits == "number" ? s.clientMaxWindowBits > n.client_max_window_bits : !n.client_max_window_bits)));
          if (!r)
            throw new Error("None of the extension offers can be accepted");
          return s.serverNoContextTakeover && (r.server_no_context_takeover = true), s.clientNoContextTakeover && (r.client_no_context_takeover = true), typeof s.serverMaxWindowBits == "number" && (r.server_max_window_bits = s.serverMaxWindowBits), typeof s.clientMaxWindowBits == "number" ? r.client_max_window_bits = s.clientMaxWindowBits : (r.client_max_window_bits === true || s.clientMaxWindowBits === false) && delete r.client_max_window_bits, r;
        }
        acceptAsClient(e) {
          let s = e[0];
          if (this._options.clientNoContextTakeover === false && s.client_no_context_takeover)
            throw new Error('Unexpected parameter "client_no_context_takeover"');
          if (!s.client_max_window_bits)
            typeof this._options.clientMaxWindowBits == "number" && (s.client_max_window_bits = this._options.clientMaxWindowBits);
          else if (this._options.clientMaxWindowBits === false || typeof this._options.clientMaxWindowBits == "number" && s.client_max_window_bits > this._options.clientMaxWindowBits)
            throw new Error('Unexpected or invalid parameter "client_max_window_bits"');
          return s;
        }
        normalizeParams(e) {
          return e.forEach((s) => {
            Object.keys(s).forEach((r) => {
              let n = s[r];
              if (n.length > 1)
                throw new Error(`Parameter "${r}" must have only a single value`);
              if (n = n[0], r === "client_max_window_bits") {
                if (n !== true) {
                  let i = +n;
                  if (!Number.isInteger(i) || i < 8 || i > 15)
                    throw new TypeError(`Invalid value for parameter "${r}": ${n}`);
                  n = i;
                } else if (!this._isServer)
                  throw new TypeError(`Invalid value for parameter "${r}": ${n}`);
              } else if (r === "server_max_window_bits") {
                let i = +n;
                if (!Number.isInteger(i) || i < 8 || i > 15)
                  throw new TypeError(`Invalid value for parameter "${r}": ${n}`);
                n = i;
              } else if (r === "client_no_context_takeover" || r === "server_no_context_takeover") {
                if (n !== true)
                  throw new TypeError(`Invalid value for parameter "${r}": ${n}`);
              } else
                throw new Error(`Unknown parameter "${r}"`);
              s[r] = n;
            });
          }), e;
        }
        decompress(e, s, r) {
          de.add((n) => {
            this._decompress(e, s, (i, o) => {
              n(), r(i, o);
            });
          });
        }
        compress(e, s, r) {
          de.add((n) => {
            this._compress(e, s, (i, o) => {
              n(), r(i, o);
            });
          });
        }
        _decompress(e, s, r) {
          let n = this._isServer ? "client" : "server";
          if (!this._inflate) {
            let i = `${n}_max_window_bits`, o = typeof this.params[i] != "number" ? ie.Z_DEFAULT_WINDOWBITS : this.params[i];
            this._inflate = ie.createInflateRaw({ ...this._options.zlibInflateOptions, windowBits: o }), this._inflate[pe] = this, this._inflate[A] = 0, this._inflate[M] = [], this._inflate.on("error", vs), this._inflate.on("data", ft);
          }
          this._inflate[K] = r, this._inflate.write(e), s && this._inflate.write(ws), this._inflate.flush(() => {
            let i = this._inflate[X];
            if (i) {
              this._inflate.close(), this._inflate = null, r(i);
              return;
            }
            let o = at.concat(this._inflate[M], this._inflate[A]);
            this._inflate._readableState.endEmitted ? (this._inflate.close(), this._inflate = null) : (this._inflate[A] = 0, this._inflate[M] = [], s && this.params[`${n}_no_context_takeover`] && this._inflate.reset()), r(null, o);
          });
        }
        _compress(e, s, r) {
          let n = this._isServer ? "server" : "client";
          if (!this._deflate) {
            let i = `${n}_max_window_bits`, o = typeof this.params[i] != "number" ? ie.Z_DEFAULT_WINDOWBITS : this.params[i];
            this._deflate = ie.createDeflateRaw({ ...this._options.zlibDeflateOptions, windowBits: o }), this._deflate[A] = 0, this._deflate[M] = [], this._deflate.on("data", Ts);
          }
          this._deflate[K] = r, this._deflate.write(e), this._deflate.flush(ie.Z_SYNC_FLUSH, () => {
            if (!this._deflate)
              return;
            let i = at.concat(this._deflate[M], this._deflate[A]);
            s && (i = new bs(i.buffer, i.byteOffset, i.length - 4)), this._deflate[K] = null, this._deflate[A] = 0, this._deflate[M] = [], s && this.params[`${n}_no_context_takeover`] && this._deflate.reset(), r(null, i);
          });
        }
      };
      ct.exports = Ie;
      function Ts(t) {
        this[M].push(t), this[A] += t.length;
      }
      function ft(t) {
        if (this[A] += t.length, this[pe]._maxPayload < 1 || this[A] <= this[pe]._maxPayload) {
          this[M].push(t);
          return;
        }
        this[X] = new RangeError("Max payload size exceeded"), this[X].code = "WS_ERR_UNSUPPORTED_MESSAGE_LENGTH", this[X][lt] = 1009, this.removeListener("data", ft), this.reset();
      }
      function vs(t) {
        if (this[pe]._inflate = null, this[X]) {
          this[K](this[X]);
          return;
        }
        t[lt] = 1007, this[K](t);
      }
    });
    var Z = b((Sn, ge) => {
      "use strict";
      var { isUtf8: ht } = require("buffer"), { hasBlob: ks } = N(), Os = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0];
      function Ls(t) {
        return t >= 1e3 && t <= 1014 && t !== 1004 && t !== 1005 && t !== 1006 || t >= 3e3 && t <= 4999;
      }
      function Re(t) {
        let e = t.length, s = 0;
        for (; s < e; )
          if (!(t[s] & 128))
            s++;
          else if ((t[s] & 224) === 192) {
            if (s + 1 === e || (t[s + 1] & 192) !== 128 || (t[s] & 254) === 192)
              return false;
            s += 2;
          } else if ((t[s] & 240) === 224) {
            if (s + 2 >= e || (t[s + 1] & 192) !== 128 || (t[s + 2] & 192) !== 128 || t[s] === 224 && (t[s + 1] & 224) === 128 || t[s] === 237 && (t[s + 1] & 224) === 160)
              return false;
            s += 3;
          } else if ((t[s] & 248) === 240) {
            if (s + 3 >= e || (t[s + 1] & 192) !== 128 || (t[s + 2] & 192) !== 128 || (t[s + 3] & 192) !== 128 || t[s] === 240 && (t[s + 1] & 240) === 128 || t[s] === 244 && t[s + 1] > 143 || t[s] > 244)
              return false;
            s += 4;
          } else
            return false;
        return true;
      }
      function Cs(t) {
        return ks && typeof t == "object" && typeof t.arrayBuffer == "function" && typeof t.type == "string" && typeof t.stream == "function" && (t[Symbol.toStringTag] === "Blob" || t[Symbol.toStringTag] === "File");
      }
      ge.exports = { isBlob: Cs, isValidStatusCode: Ls, isValidUTF8: Re, tokenChars: Os };
      if (ht)
        ge.exports.isValidUTF8 = function(t) {
          return t.length < 24 ? Re(t) : ht(t);
        };
      else if (!process.env.WS_NO_UTF_8_VALIDATE)
        try {
          let t = require("utf-8-validate");
          ge.exports.isValidUTF8 = function(e) {
            return e.length < 32 ? Re(e) : t(e);
          };
        } catch {
        }
    });
    var qe = b((En, yt) => {
      "use strict";
      var { Writable: Ps } = require("stream"), ut = J(), { BINARY_TYPES: Ns, EMPTY_BUFFER: dt, kStatusCode: As, kWebSocket: Bs } = N(), { concat: Me, toArrayBuffer: Is, unmask: Rs } = ne(), { isValidStatusCode: Ms, isValidUTF8: pt } = Z(), _e2 = Buffer[Symbol.species], T = 0, gt = 1, _t2 = 2, mt = 3, De = 4, Ue = 5, me = 6, Fe = class extends Ps {
        constructor(e = {}) {
          super(), this._allowSynchronousEvents = e.allowSynchronousEvents !== void 0 ? e.allowSynchronousEvents : true, this._binaryType = e.binaryType || Ns[0], this._extensions = e.extensions || {}, this._isServer = !!e.isServer, this._maxBufferedChunks = e.maxBufferedChunks | 0, this._maxFragments = e.maxFragments | 0, this._maxPayload = e.maxPayload | 0, this._skipUTF8Validation = !!e.skipUTF8Validation, this[Bs] = void 0, this._bufferedBytes = 0, this._buffers = [], this._compressed = false, this._payloadLength = 0, this._mask = void 0, this._fragmented = 0, this._masked = false, this._fin = false, this._opcode = 0, this._totalPayloadLength = 0, this._messageLength = 0, this._numFragments = 0, this._fragments = [], this._errored = false, this._loop = false, this._state = T;
        }
        _write(e, s, r) {
          if (this._opcode === 8 && this._state == T)
            return r();
          if (this._maxBufferedChunks > 0 && this._buffers.length >= this._maxBufferedChunks) {
            r(this.createError(RangeError, "Too many buffered chunks", false, 1008, "WS_ERR_TOO_MANY_BUFFERED_PARTS"));
            return;
          }
          this._bufferedBytes += e.length, this._buffers.push(e), this.startLoop(r);
        }
        consume(e) {
          if (this._bufferedBytes -= e, e === this._buffers[0].length)
            return this._buffers.shift();
          if (e < this._buffers[0].length) {
            let r = this._buffers[0];
            return this._buffers[0] = new _e2(r.buffer, r.byteOffset + e, r.length - e), new _e2(r.buffer, r.byteOffset, e);
          }
          let s = Buffer.allocUnsafe(e);
          do {
            let r = this._buffers[0], n = s.length - e;
            e >= r.length ? s.set(this._buffers.shift(), n) : (s.set(new Uint8Array(r.buffer, r.byteOffset, e), n), this._buffers[0] = new _e2(r.buffer, r.byteOffset + e, r.length - e)), e -= r.length;
          } while (e > 0);
          return s;
        }
        startLoop(e) {
          this._loop = true;
          do
            switch (this._state) {
              case T:
                this.getInfo(e);
                break;
              case gt:
                this.getPayloadLength16(e);
                break;
              case _t2:
                this.getPayloadLength64(e);
                break;
              case mt:
                this.getMask();
                break;
              case De:
                this.getData(e);
                break;
              case Ue:
              case me:
                this._loop = false;
                return;
            }
          while (this._loop);
          this._errored || e();
        }
        getInfo(e) {
          if (this._bufferedBytes < 2) {
            this._loop = false;
            return;
          }
          let s = this.consume(2);
          if (s[0] & 48) {
            let n = this.createError(RangeError, "RSV2 and RSV3 must be clear", true, 1002, "WS_ERR_UNEXPECTED_RSV_2_3");
            e(n);
            return;
          }
          let r = (s[0] & 64) === 64;
          if (r && !this._extensions[ut.extensionName]) {
            let n = this.createError(RangeError, "RSV1 must be clear", true, 1002, "WS_ERR_UNEXPECTED_RSV_1");
            e(n);
            return;
          }
          if (this._fin = (s[0] & 128) === 128, this._opcode = s[0] & 15, this._payloadLength = s[1] & 127, this._opcode === 0) {
            if (r) {
              let n = this.createError(RangeError, "RSV1 must be clear", true, 1002, "WS_ERR_UNEXPECTED_RSV_1");
              e(n);
              return;
            }
            if (!this._fragmented) {
              let n = this.createError(RangeError, "invalid opcode 0", true, 1002, "WS_ERR_INVALID_OPCODE");
              e(n);
              return;
            }
            this._opcode = this._fragmented;
          } else if (this._opcode === 1 || this._opcode === 2) {
            if (this._fragmented) {
              let n = this.createError(RangeError, `invalid opcode ${this._opcode}`, true, 1002, "WS_ERR_INVALID_OPCODE");
              e(n);
              return;
            }
            this._compressed = r;
          } else if (this._opcode > 7 && this._opcode < 11) {
            if (!this._fin) {
              let n = this.createError(RangeError, "FIN must be set", true, 1002, "WS_ERR_EXPECTED_FIN");
              e(n);
              return;
            }
            if (r) {
              let n = this.createError(RangeError, "RSV1 must be clear", true, 1002, "WS_ERR_UNEXPECTED_RSV_1");
              e(n);
              return;
            }
            if (this._payloadLength > 125 || this._opcode === 8 && this._payloadLength === 1) {
              let n = this.createError(RangeError, `invalid payload length ${this._payloadLength}`, true, 1002, "WS_ERR_INVALID_CONTROL_PAYLOAD_LENGTH");
              e(n);
              return;
            }
          } else {
            let n = this.createError(RangeError, `invalid opcode ${this._opcode}`, true, 1002, "WS_ERR_INVALID_OPCODE");
            e(n);
            return;
          }
          if (!this._fin && !this._fragmented && (this._fragmented = this._opcode), this._masked = (s[1] & 128) === 128, this._isServer) {
            if (!this._masked) {
              let n = this.createError(RangeError, "MASK must be set", true, 1002, "WS_ERR_EXPECTED_MASK");
              e(n);
              return;
            }
          } else if (this._masked) {
            let n = this.createError(RangeError, "MASK must be clear", true, 1002, "WS_ERR_UNEXPECTED_MASK");
            e(n);
            return;
          }
          this._payloadLength === 126 ? this._state = gt : this._payloadLength === 127 ? this._state = _t2 : this.haveLength(e);
        }
        getPayloadLength16(e) {
          if (this._bufferedBytes < 2) {
            this._loop = false;
            return;
          }
          this._payloadLength = this.consume(2).readUInt16BE(0), this.haveLength(e);
        }
        getPayloadLength64(e) {
          if (this._bufferedBytes < 8) {
            this._loop = false;
            return;
          }
          let s = this.consume(8), r = s.readUInt32BE(0);
          if (r > Math.pow(2, 21) - 1) {
            let n = this.createError(RangeError, "Unsupported WebSocket frame: payload length > 2^53 - 1", false, 1009, "WS_ERR_UNSUPPORTED_DATA_PAYLOAD_LENGTH");
            e(n);
            return;
          }
          this._payloadLength = r * Math.pow(2, 32) + s.readUInt32BE(4), this.haveLength(e);
        }
        haveLength(e) {
          if (this._payloadLength && this._opcode < 8 && (this._totalPayloadLength += this._payloadLength, this._totalPayloadLength > this._maxPayload && this._maxPayload > 0)) {
            let s = this.createError(RangeError, "Max payload size exceeded", false, 1009, "WS_ERR_UNSUPPORTED_MESSAGE_LENGTH");
            e(s);
            return;
          }
          this._masked ? this._state = mt : this._state = De;
        }
        getMask() {
          if (this._bufferedBytes < 4) {
            this._loop = false;
            return;
          }
          this._mask = this.consume(4), this._state = De;
        }
        getData(e) {
          let s = dt;
          if (this._payloadLength) {
            if (this._bufferedBytes < this._payloadLength) {
              this._loop = false;
              return;
            }
            s = this.consume(this._payloadLength), this._masked && this._mask[0] | this._mask[1] | this._mask[2] | this._mask[3] && Rs(s, this._mask);
          }
          if (this._opcode > 7) {
            this.controlMessage(s, e);
            return;
          }
          if (this._maxFragments > 0 && ++this._numFragments > this._maxFragments) {
            let r = this.createError(RangeError, "Too many message fragments", false, 1008, "WS_ERR_TOO_MANY_BUFFERED_PARTS");
            e(r);
            return;
          }
          if (this._compressed) {
            this._state = Ue, this.decompress(s, e);
            return;
          }
          s.length && (this._messageLength = this._totalPayloadLength, this._fragments.push(s)), this.dataMessage(e);
        }
        decompress(e, s) {
          this._extensions[ut.extensionName].decompress(e, this._fin, (n, i) => {
            if (n)
              return s(n);
            if (i.length) {
              if (this._messageLength += i.length, this._messageLength > this._maxPayload && this._maxPayload > 0) {
                let o = this.createError(RangeError, "Max payload size exceeded", false, 1009, "WS_ERR_UNSUPPORTED_MESSAGE_LENGTH");
                s(o);
                return;
              }
              this._fragments.push(i);
            }
            this.dataMessage(s), this._state === T && this.startLoop(s);
          });
        }
        dataMessage(e) {
          if (!this._fin) {
            this._state = T;
            return;
          }
          let s = this._messageLength, r = this._fragments;
          if (this._totalPayloadLength = 0, this._messageLength = 0, this._fragmented = 0, this._numFragments = 0, this._fragments = [], this._opcode === 2) {
            let n;
            this._binaryType === "nodebuffer" ? n = Me(r, s) : this._binaryType === "arraybuffer" ? n = Is(Me(r, s)) : this._binaryType === "blob" ? n = new Blob(r) : n = r, this._allowSynchronousEvents ? (this.emit("message", n, true), this._state = T) : (this._state = me, setImmediate(() => {
              this.emit("message", n, true), this._state = T, this.startLoop(e);
            }));
          } else {
            let n = Me(r, s);
            if (!this._skipUTF8Validation && !pt(n)) {
              let i = this.createError(Error, "invalid UTF-8 sequence", true, 1007, "WS_ERR_INVALID_UTF8");
              e(i);
              return;
            }
            this._state === Ue || this._allowSynchronousEvents ? (this.emit("message", n, false), this._state = T) : (this._state = me, setImmediate(() => {
              this.emit("message", n, false), this._state = T, this.startLoop(e);
            }));
          }
        }
        controlMessage(e, s) {
          if (this._opcode === 8) {
            if (e.length === 0)
              this._loop = false, this.emit("conclude", 1005, dt), this.end();
            else {
              let r = e.readUInt16BE(0);
              if (!Ms(r)) {
                let i = this.createError(RangeError, `invalid status code ${r}`, true, 1002, "WS_ERR_INVALID_CLOSE_CODE");
                s(i);
                return;
              }
              let n = new _e2(e.buffer, e.byteOffset + 2, e.length - 2);
              if (!this._skipUTF8Validation && !pt(n)) {
                let i = this.createError(Error, "invalid UTF-8 sequence", true, 1007, "WS_ERR_INVALID_UTF8");
                s(i);
                return;
              }
              this._loop = false, this.emit("conclude", r, n), this.end();
            }
            this._state = T;
            return;
          }
          this._allowSynchronousEvents ? (this.emit(this._opcode === 9 ? "ping" : "pong", e), this._state = T) : (this._state = me, setImmediate(() => {
            this.emit(this._opcode === 9 ? "ping" : "pong", e), this._state = T, this.startLoop(s);
          }));
        }
        createError(e, s, r, n, i) {
          this._loop = false, this._errored = true;
          let o = new e(r ? `Invalid WebSocket frame: ${s}` : s);
          return Error.captureStackTrace(o, this.createError), o.code = i, o[As] = n, o;
        }
      };
      yt.exports = Fe;
    });
    var je = b((bn, xt) => {
      "use strict";
      var { Duplex: xn } = require("stream"), { randomFillSync: Ds } = require("crypto"), { types: { isUint8Array: Us } } = require("util"), St = J(), { EMPTY_BUFFER: Fs, kWebSocket: qs, NOOP: Ws } = N(), { isBlob: Q, isValidStatusCode: $s } = Z(), { mask: Et, toBuffer: W } = ne(), v = Symbol("kByteLength"), js = Buffer.alloc(4), ye = 8 * 1024, $, ee = ye, O = 0, Gs = 1, Vs = 2, We = class t {
        constructor(e, s, r) {
          this._extensions = s || {}, r && (this._generateMask = r, this._maskBuffer = Buffer.alloc(4)), this._socket = e, this._firstFragment = true, this._compress = false, this._bufferedBytes = 0, this._queue = [], this._state = O, this.onerror = Ws, this[qs] = void 0;
        }
        static frame(e, s) {
          let r, n = false, i = 2, o = false;
          s.mask && (r = s.maskBuffer || js, s.generateMask ? s.generateMask(r) : (ee === ye && ($ === void 0 && ($ = Buffer.alloc(ye)), Ds($, 0, ye), ee = 0), r[0] = $[ee++], r[1] = $[ee++], r[2] = $[ee++], r[3] = $[ee++]), o = (r[0] | r[1] | r[2] | r[3]) === 0, i = 6);
          let l;
          typeof e == "string" ? (!s.mask || o) && s[v] !== void 0 ? l = s[v] : (e = Buffer.from(e), l = e.length) : (l = e.length, n = s.mask && s.readOnly && !o);
          let f = l;
          l >= 65536 ? (i += 8, f = 127) : l > 125 && (i += 2, f = 126);
          let a = Buffer.allocUnsafe(n ? l + i : i);
          return a[0] = s.fin ? s.opcode | 128 : s.opcode, s.rsv1 && (a[0] |= 64), a[1] = f, f === 126 ? a.writeUInt16BE(l, 2) : f === 127 && (a[2] = a[3] = 0, a.writeUIntBE(l, 4, 6)), s.mask ? (a[1] |= 128, a[i - 4] = r[0], a[i - 3] = r[1], a[i - 2] = r[2], a[i - 1] = r[3], o ? [a, e] : n ? (Et(e, r, a, i, l), [a]) : (Et(e, r, e, 0, l), [a, e])) : [a, e];
        }
        close(e, s, r, n) {
          let i;
          if (e === void 0)
            i = Fs;
          else {
            if (typeof e != "number" || !$s(e))
              throw new TypeError("First argument must be a valid error code number");
            if (s === void 0 || !s.length)
              i = Buffer.allocUnsafe(2), i.writeUInt16BE(e, 0);
            else {
              let l = Buffer.byteLength(s);
              if (l > 123)
                throw new RangeError("The message must not be greater than 123 bytes");
              if (i = Buffer.allocUnsafe(2 + l), i.writeUInt16BE(e, 0), typeof s == "string")
                i.write(s, 2);
              else if (Us(s))
                i.set(s, 2);
              else
                throw new TypeError("Second argument must be a string or a Uint8Array");
            }
          }
          let o = { [v]: i.length, fin: true, generateMask: this._generateMask, mask: r, maskBuffer: this._maskBuffer, opcode: 8, readOnly: false, rsv1: false };
          this._state !== O ? this.enqueue([this.dispatch, i, false, o, n]) : this.sendFrame(t.frame(i, o), n);
        }
        ping(e, s, r) {
          let n, i;
          if (typeof e == "string" ? (n = Buffer.byteLength(e), i = false) : Q(e) ? (n = e.size, i = false) : (e = W(e), n = e.length, i = W.readOnly), n > 125)
            throw new RangeError("The data size must not be greater than 125 bytes");
          let o = { [v]: n, fin: true, generateMask: this._generateMask, mask: s, maskBuffer: this._maskBuffer, opcode: 9, readOnly: i, rsv1: false };
          Q(e) ? this._state !== O ? this.enqueue([this.getBlobData, e, false, o, r]) : this.getBlobData(e, false, o, r) : this._state !== O ? this.enqueue([this.dispatch, e, false, o, r]) : this.sendFrame(t.frame(e, o), r);
        }
        pong(e, s, r) {
          let n, i;
          if (typeof e == "string" ? (n = Buffer.byteLength(e), i = false) : Q(e) ? (n = e.size, i = false) : (e = W(e), n = e.length, i = W.readOnly), n > 125)
            throw new RangeError("The data size must not be greater than 125 bytes");
          let o = { [v]: n, fin: true, generateMask: this._generateMask, mask: s, maskBuffer: this._maskBuffer, opcode: 10, readOnly: i, rsv1: false };
          Q(e) ? this._state !== O ? this.enqueue([this.getBlobData, e, false, o, r]) : this.getBlobData(e, false, o, r) : this._state !== O ? this.enqueue([this.dispatch, e, false, o, r]) : this.sendFrame(t.frame(e, o), r);
        }
        send(e, s, r) {
          let n = this._extensions[St.extensionName], i = s.binary ? 2 : 1, o = s.compress, l, f;
          typeof e == "string" ? (l = Buffer.byteLength(e), f = false) : Q(e) ? (l = e.size, f = false) : (e = W(e), l = e.length, f = W.readOnly), this._firstFragment ? (this._firstFragment = false, o && n && n.params[n._isServer ? "server_no_context_takeover" : "client_no_context_takeover"] && (o = l >= n._threshold), this._compress = o) : (o = false, i = 0), s.fin && (this._firstFragment = true);
          let a = { [v]: l, fin: s.fin, generateMask: this._generateMask, mask: s.mask, maskBuffer: this._maskBuffer, opcode: i, readOnly: f, rsv1: o };
          Q(e) ? this._state !== O ? this.enqueue([this.getBlobData, e, this._compress, a, r]) : this.getBlobData(e, this._compress, a, r) : this._state !== O ? this.enqueue([this.dispatch, e, this._compress, a, r]) : this.dispatch(e, this._compress, a, r);
        }
        getBlobData(e, s, r, n) {
          this._bufferedBytes += r[v], this._state = Vs, e.arrayBuffer().then((i) => {
            if (this._socket.destroyed) {
              let l = new Error("The socket was closed while the blob was being read");
              process.nextTick($e, this, l, n);
              return;
            }
            this._bufferedBytes -= r[v];
            let o = W(i);
            s ? this.dispatch(o, s, r, n) : (this._state = O, this.sendFrame(t.frame(o, r), n), this.dequeue());
          }).catch((i) => {
            process.nextTick(zs, this, i, n);
          });
        }
        dispatch(e, s, r, n) {
          if (!s) {
            this.sendFrame(t.frame(e, r), n);
            return;
          }
          let i = this._extensions[St.extensionName];
          this._bufferedBytes += r[v], this._state = Gs, i.compress(e, r.fin, (o, l) => {
            if (this._socket.destroyed) {
              let f = new Error("The socket was closed while data was being compressed");
              $e(this, f, n);
              return;
            }
            this._bufferedBytes -= r[v], this._state = O, r.readOnly = false, this.sendFrame(t.frame(l, r), n), this.dequeue();
          });
        }
        dequeue() {
          for (; this._state === O && this._queue.length; ) {
            let e = this._queue.shift();
            this._bufferedBytes -= e[3][v], Reflect.apply(e[0], this, e.slice(1));
          }
        }
        enqueue(e) {
          this._bufferedBytes += e[3][v], this._queue.push(e);
        }
        sendFrame(e, s) {
          e.length === 2 ? (this._socket.cork(), this._socket.write(e[0]), this._socket.write(e[1], s), this._socket.uncork()) : this._socket.write(e[0], s);
        }
      };
      xt.exports = We;
      function $e(t, e, s) {
        typeof s == "function" && s(e);
        for (let r = 0; r < t._queue.length; r++) {
          let n = t._queue[r], i = n[n.length - 1];
          typeof i == "function" && i(e);
        }
      }
      function zs(t, e, s) {
        $e(t, e, s), t.onerror(e);
      }
    });
    var Pt = b((wn, Ct) => {
      "use strict";
      var { kForOnEventAttribute: oe, kListener: Ge } = N(), bt = Symbol("kCode"), wt = Symbol("kData"), Tt = Symbol("kError"), vt = Symbol("kMessage"), kt = Symbol("kReason"), te = Symbol("kTarget"), Ot = Symbol("kType"), Lt = Symbol("kWasClean"), B = class {
        constructor(e) {
          this[te] = null, this[Ot] = e;
        }
        get target() {
          return this[te];
        }
        get type() {
          return this[Ot];
        }
      };
      Object.defineProperty(B.prototype, "target", { enumerable: true });
      Object.defineProperty(B.prototype, "type", { enumerable: true });
      var j = class extends B {
        constructor(e, s = {}) {
          super(e), this[bt] = s.code === void 0 ? 0 : s.code, this[kt] = s.reason === void 0 ? "" : s.reason, this[Lt] = s.wasClean === void 0 ? false : s.wasClean;
        }
        get code() {
          return this[bt];
        }
        get reason() {
          return this[kt];
        }
        get wasClean() {
          return this[Lt];
        }
      };
      Object.defineProperty(j.prototype, "code", { enumerable: true });
      Object.defineProperty(j.prototype, "reason", { enumerable: true });
      Object.defineProperty(j.prototype, "wasClean", { enumerable: true });
      var se = class extends B {
        constructor(e, s = {}) {
          super(e), this[Tt] = s.error === void 0 ? null : s.error, this[vt] = s.message === void 0 ? "" : s.message;
        }
        get error() {
          return this[Tt];
        }
        get message() {
          return this[vt];
        }
      };
      Object.defineProperty(se.prototype, "error", { enumerable: true });
      Object.defineProperty(se.prototype, "message", { enumerable: true });
      var ae = class extends B {
        constructor(e, s = {}) {
          super(e), this[wt] = s.data === void 0 ? null : s.data;
        }
        get data() {
          return this[wt];
        }
      };
      Object.defineProperty(ae.prototype, "data", { enumerable: true });
      var Hs = { addEventListener(t, e, s = {}) {
        for (let n of this.listeners(t))
          if (!s[oe] && n[Ge] === e && !n[oe])
            return;
        let r;
        if (t === "message")
          r = function(i, o) {
            let l = new ae("message", { data: o ? i : i.toString() });
            l[te] = this, Se(e, this, l);
          };
        else if (t === "close")
          r = function(i, o) {
            let l = new j("close", { code: i, reason: o.toString(), wasClean: this._closeFrameReceived && this._closeFrameSent });
            l[te] = this, Se(e, this, l);
          };
        else if (t === "error")
          r = function(i) {
            let o = new se("error", { error: i, message: i.message });
            o[te] = this, Se(e, this, o);
          };
        else if (t === "open")
          r = function() {
            let i = new B("open");
            i[te] = this, Se(e, this, i);
          };
        else
          return;
        r[oe] = !!s[oe], r[Ge] = e, s.once ? this.once(t, r) : this.on(t, r);
      }, removeEventListener(t, e) {
        for (let s of this.listeners(t))
          if (s[Ge] === e && !s[oe]) {
            this.removeListener(t, s);
            break;
          }
      } };
      Ct.exports = { CloseEvent: j, ErrorEvent: se, Event: B, EventTarget: Hs, MessageEvent: ae };
      function Se(t, e, s) {
        typeof t == "object" && t.handleEvent ? t.handleEvent.call(t, s) : t.call(e, s);
      }
    });
    var Ee = b((Tn, Nt) => {
      "use strict";
      var { tokenChars: le } = Z();
      function L(t, e, s) {
        t[e] === void 0 ? t[e] = [s] : t[e].push(s);
      }
      function Ys(t) {
        let e = /* @__PURE__ */ Object.create(null), s = /* @__PURE__ */ Object.create(null), r = false, n = false, i = false, o, l, f = -1, a = -1, c = -1, h = 0;
        for (; h < t.length; h++)
          if (a = t.charCodeAt(h), o === void 0)
            if (c === -1 && le[a] === 1)
              f === -1 && (f = h);
            else if (h !== 0 && (a === 32 || a === 9))
              c === -1 && f !== -1 && (c = h);
            else if (a === 59 || a === 44) {
              if (f === -1)
                throw new SyntaxError(`Unexpected character at index ${h}`);
              c === -1 && (c = h);
              let _ = t.slice(f, c);
              a === 44 ? (L(e, _, s), s = /* @__PURE__ */ Object.create(null)) : o = _, f = c = -1;
            } else
              throw new SyntaxError(`Unexpected character at index ${h}`);
          else if (l === void 0)
            if (c === -1 && le[a] === 1)
              f === -1 && (f = h);
            else if (a === 32 || a === 9)
              c === -1 && f !== -1 && (c = h);
            else if (a === 59 || a === 44) {
              if (f === -1)
                throw new SyntaxError(`Unexpected character at index ${h}`);
              c === -1 && (c = h), L(s, t.slice(f, c), true), a === 44 && (L(e, o, s), s = /* @__PURE__ */ Object.create(null), o = void 0), f = c = -1;
            } else if (a === 61 && f !== -1 && c === -1)
              l = t.slice(f, h), f = c = -1;
            else
              throw new SyntaxError(`Unexpected character at index ${h}`);
          else if (n) {
            if (le[a] !== 1)
              throw new SyntaxError(`Unexpected character at index ${h}`);
            f === -1 ? f = h : r || (r = true), n = false;
          } else if (i)
            if (le[a] === 1)
              f === -1 && (f = h);
            else if (a === 34 && f !== -1)
              i = false, c = h;
            else if (a === 92)
              n = true;
            else
              throw new SyntaxError(`Unexpected character at index ${h}`);
          else if (a === 34 && t.charCodeAt(h - 1) === 61)
            i = true;
          else if (c === -1 && le[a] === 1)
            f === -1 && (f = h);
          else if (f !== -1 && (a === 32 || a === 9))
            c === -1 && (c = h);
          else if (a === 59 || a === 44) {
            if (f === -1)
              throw new SyntaxError(`Unexpected character at index ${h}`);
            c === -1 && (c = h);
            let _ = t.slice(f, c);
            r && (_ = _.replace(/\\/g, ""), r = false), L(s, l, _), a === 44 && (L(e, o, s), s = /* @__PURE__ */ Object.create(null), o = void 0), l = void 0, f = c = -1;
          } else
            throw new SyntaxError(`Unexpected character at index ${h}`);
        if (f === -1 || i || a === 32 || a === 9)
          throw new SyntaxError("Unexpected end of input");
        c === -1 && (c = h);
        let p = t.slice(f, c);
        return o === void 0 ? L(e, p, s) : (l === void 0 ? L(s, p, true) : r ? L(s, l, p.replace(/\\/g, "")) : L(s, l, p), L(e, o, s)), e;
      }
      function Ks(t) {
        return Object.keys(t).map((e) => {
          let s = t[e];
          return Array.isArray(s) || (s = [s]), s.map((r) => [e].concat(Object.keys(r).map((n) => {
            let i = r[n];
            return Array.isArray(i) || (i = [i]), i.map((o) => o === true ? n : `${n}=${o}`).join("; ");
          })).join("; ")).join(", ");
        }).join(", ");
      }
      Nt.exports = { format: Ks, parse: Ys };
    });
    var Te = b((On, jt) => {
      "use strict";
      var Xs = require("events"), Js = require("https"), Zs = require("http"), It = require("net"), Qs = require("tls"), { randomBytes: er, createHash: tr } = require("crypto"), { Duplex: vn, Readable: kn } = require("stream"), { URL: Ve } = require("url"), D = J(), sr = qe(), rr = je(), { isBlob: nr } = Z(), { BINARY_TYPES: At, CLOSE_TIMEOUT: ir, EMPTY_BUFFER: xe, GUID: or, kForOnEventAttribute: ze, kListener: ar, kStatusCode: lr, kWebSocket: S, NOOP: Rt } = N(), { EventTarget: { addEventListener: fr, removeEventListener: cr } } = Pt(), { format: hr, parse: ur } = Ee(), { toBuffer: dr } = ne(), Mt = Symbol("kAborted"), He = [8, 13], I = ["CONNECTING", "OPEN", "CLOSING", "CLOSED"], pr = /^[!#$%&'*+\-.0-9A-Z^_`|a-z~]+$/, g = class t extends Xs {
        constructor(e, s, r) {
          super(), this._binaryType = At[0], this._closeCode = 1006, this._closeFrameReceived = false, this._closeFrameSent = false, this._closeMessage = xe, this._closeTimer = null, this._errorEmitted = false, this._extensions = {}, this._paused = false, this._protocol = "", this._readyState = t.CONNECTING, this._receiver = null, this._sender = null, this._socket = null, e !== null ? (this._bufferedAmount = 0, this._isServer = false, this._redirects = 0, s === void 0 ? s = [] : Array.isArray(s) || (typeof s == "object" && s !== null ? (r = s, s = []) : s = [s]), Dt(this, e, s, r)) : (this._autoPong = r.autoPong, this._closeTimeout = r.closeTimeout, this._isServer = true);
        }
        get binaryType() {
          return this._binaryType;
        }
        set binaryType(e) {
          At.includes(e) && (this._binaryType = e, this._receiver && (this._receiver._binaryType = e));
        }
        get bufferedAmount() {
          return this._socket ? this._socket._writableState.length + this._sender._bufferedBytes : this._bufferedAmount;
        }
        get extensions() {
          return Object.keys(this._extensions).join();
        }
        get isPaused() {
          return this._paused;
        }
        get onclose() {
          return null;
        }
        get onerror() {
          return null;
        }
        get onopen() {
          return null;
        }
        get onmessage() {
          return null;
        }
        get protocol() {
          return this._protocol;
        }
        get readyState() {
          return this._readyState;
        }
        get url() {
          return this._url;
        }
        setSocket(e, s, r) {
          let n = new sr({ allowSynchronousEvents: r.allowSynchronousEvents, binaryType: this.binaryType, extensions: this._extensions, isServer: this._isServer, maxBufferedChunks: r.maxBufferedChunks, maxFragments: r.maxFragments, maxPayload: r.maxPayload, skipUTF8Validation: r.skipUTF8Validation }), i = new rr(e, this._extensions, r.generateMask);
          this._receiver = n, this._sender = i, this._socket = e, n[S] = this, i[S] = this, e[S] = this, n.on("conclude", mr), n.on("drain", yr), n.on("error", Sr), n.on("message", Er), n.on("ping", xr), n.on("pong", br), i.onerror = wr, e.setTimeout && e.setTimeout(0), e.setNoDelay && e.setNoDelay(), s.length > 0 && e.unshift(s), e.on("close", qt), e.on("data", we), e.on("end", Wt), e.on("error", $t), this._readyState = t.OPEN, this.emit("open");
        }
        emitClose() {
          if (!this._socket) {
            this._readyState = t.CLOSED, this.emit("close", this._closeCode, this._closeMessage);
            return;
          }
          this._extensions[D.extensionName] && this._extensions[D.extensionName].cleanup(), this._receiver.removeAllListeners(), this._readyState = t.CLOSED, this.emit("close", this._closeCode, this._closeMessage);
        }
        close(e, s) {
          if (this.readyState !== t.CLOSED) {
            if (this.readyState === t.CONNECTING) {
              w(this, this._req, "WebSocket was closed before the connection was established");
              return;
            }
            if (this.readyState === t.CLOSING) {
              this._closeFrameSent && (this._closeFrameReceived || this._receiver._writableState.errorEmitted) && this._socket.end();
              return;
            }
            this._readyState = t.CLOSING, this._sender.close(e, s, !this._isServer, (r) => {
              r || (this._closeFrameSent = true, (this._closeFrameReceived || this._receiver._writableState.errorEmitted) && this._socket.end());
            }), Ft(this);
          }
        }
        pause() {
          this.readyState === t.CONNECTING || this.readyState === t.CLOSED || (this._paused = true, this._socket.pause());
        }
        ping(e, s, r) {
          if (this.readyState === t.CONNECTING)
            throw new Error("WebSocket is not open: readyState 0 (CONNECTING)");
          if (typeof e == "function" ? (r = e, e = s = void 0) : typeof s == "function" && (r = s, s = void 0), typeof e == "number" && (e = e.toString()), this.readyState !== t.OPEN) {
            Ye(this, e, r);
            return;
          }
          s === void 0 && (s = !this._isServer), this._sender.ping(e || xe, s, r);
        }
        pong(e, s, r) {
          if (this.readyState === t.CONNECTING)
            throw new Error("WebSocket is not open: readyState 0 (CONNECTING)");
          if (typeof e == "function" ? (r = e, e = s = void 0) : typeof s == "function" && (r = s, s = void 0), typeof e == "number" && (e = e.toString()), this.readyState !== t.OPEN) {
            Ye(this, e, r);
            return;
          }
          s === void 0 && (s = !this._isServer), this._sender.pong(e || xe, s, r);
        }
        resume() {
          this.readyState === t.CONNECTING || this.readyState === t.CLOSED || (this._paused = false, this._receiver._writableState.needDrain || this._socket.resume());
        }
        send(e, s, r) {
          if (this.readyState === t.CONNECTING)
            throw new Error("WebSocket is not open: readyState 0 (CONNECTING)");
          if (typeof s == "function" && (r = s, s = {}), typeof e == "number" && (e = e.toString()), this.readyState !== t.OPEN) {
            Ye(this, e, r);
            return;
          }
          let n = { binary: typeof e != "string", mask: !this._isServer, compress: true, fin: true, ...s };
          this._extensions[D.extensionName] || (n.compress = false), this._sender.send(e || xe, n, r);
        }
        terminate() {
          if (this.readyState !== t.CLOSED) {
            if (this.readyState === t.CONNECTING) {
              w(this, this._req, "WebSocket was closed before the connection was established");
              return;
            }
            this._socket && (this._readyState = t.CLOSING, this._socket.destroy());
          }
        }
      };
      Object.defineProperty(g, "CONNECTING", { enumerable: true, value: I.indexOf("CONNECTING") });
      Object.defineProperty(g.prototype, "CONNECTING", { enumerable: true, value: I.indexOf("CONNECTING") });
      Object.defineProperty(g, "OPEN", { enumerable: true, value: I.indexOf("OPEN") });
      Object.defineProperty(g.prototype, "OPEN", { enumerable: true, value: I.indexOf("OPEN") });
      Object.defineProperty(g, "CLOSING", { enumerable: true, value: I.indexOf("CLOSING") });
      Object.defineProperty(g.prototype, "CLOSING", { enumerable: true, value: I.indexOf("CLOSING") });
      Object.defineProperty(g, "CLOSED", { enumerable: true, value: I.indexOf("CLOSED") });
      Object.defineProperty(g.prototype, "CLOSED", { enumerable: true, value: I.indexOf("CLOSED") });
      ["binaryType", "bufferedAmount", "extensions", "isPaused", "protocol", "readyState", "url"].forEach((t) => {
        Object.defineProperty(g.prototype, t, { enumerable: true });
      });
      ["open", "error", "close", "message"].forEach((t) => {
        Object.defineProperty(g.prototype, `on${t}`, { enumerable: true, get() {
          for (let e of this.listeners(t))
            if (e[ze])
              return e[ar];
          return null;
        }, set(e) {
          for (let s of this.listeners(t))
            if (s[ze]) {
              this.removeListener(t, s);
              break;
            }
          typeof e == "function" && this.addEventListener(t, e, { [ze]: true });
        } });
      });
      g.prototype.addEventListener = fr;
      g.prototype.removeEventListener = cr;
      jt.exports = g;
      function Dt(t, e, s, r) {
        let n = { allowSynchronousEvents: true, autoPong: true, closeTimeout: ir, protocolVersion: He[1], maxBufferedChunks: 262144, maxFragments: 16384, maxPayload: 104857600, skipUTF8Validation: false, perMessageDeflate: true, followRedirects: false, maxRedirects: 10, ...r, socketPath: void 0, hostname: void 0, protocol: void 0, timeout: void 0, method: "GET", host: void 0, path: void 0, port: void 0 };
        if (t._autoPong = n.autoPong, t._closeTimeout = n.closeTimeout, !He.includes(n.protocolVersion))
          throw new RangeError(`Unsupported protocol version: ${n.protocolVersion} (supported versions: ${He.join(", ")})`);
        let i;
        if (e instanceof Ve)
          i = e;
        else
          try {
            i = new Ve(e);
          } catch {
            throw new SyntaxError(`Invalid URL: ${e}`);
          }
        i.protocol === "http:" ? i.protocol = "ws:" : i.protocol === "https:" && (i.protocol = "wss:"), t._url = i.href;
        let o = i.protocol === "wss:", l = i.protocol === "ws+unix:", f;
        if (i.protocol !== "ws:" && !o && !l ? f = `The URL's protocol must be one of "ws:", "wss:", "http:", "https:", or "ws+unix:"` : l && !i.pathname ? f = "The URL's pathname is empty" : i.hash && (f = "The URL contains a fragment identifier"), f) {
          let u = new SyntaxError(f);
          if (t._redirects === 0)
            throw u;
          be(t, u);
          return;
        }
        let a = o ? 443 : 80, c = er(16).toString("base64"), h = o ? Js.request : Zs.request, p = /* @__PURE__ */ new Set(), _;
        if (n.createConnection = n.createConnection || (o ? _r : gr), n.defaultPort = n.defaultPort || a, n.port = i.port || a, n.host = i.hostname.startsWith("[") ? i.hostname.slice(1, -1) : i.hostname, n.headers = { ...n.headers, "Sec-WebSocket-Version": n.protocolVersion, "Sec-WebSocket-Key": c, Connection: "Upgrade", Upgrade: "websocket" }, n.path = i.pathname + i.search, n.timeout = n.handshakeTimeout, n.perMessageDeflate && (_ = new D({ ...n.perMessageDeflate, isServer: false, maxPayload: n.maxPayload }), n.headers["Sec-WebSocket-Extensions"] = hr({ [D.extensionName]: _.offer() })), s.length) {
          for (let u of s) {
            if (typeof u != "string" || !pr.test(u) || p.has(u))
              throw new SyntaxError("An invalid or duplicated subprotocol was specified");
            p.add(u);
          }
          n.headers["Sec-WebSocket-Protocol"] = s.join(",");
        }
        if (n.origin && (n.protocolVersion < 13 ? n.headers["Sec-WebSocket-Origin"] = n.origin : n.headers.Origin = n.origin), (i.username || i.password) && (n.auth = `${i.username}:${i.password}`), l) {
          let u = n.path.split(":");
          n.socketPath = u[0], n.path = u[1];
        }
        let m;
        if (n.followRedirects) {
          if (t._redirects === 0) {
            t._originalIpc = l, t._originalSecure = o, t._originalHostOrSocketPath = l ? n.socketPath : i.host;
            let u = r && r.headers;
            if (r = { ...r, headers: {} }, u)
              for (let [y, R] of Object.entries(u))
                r.headers[y.toLowerCase()] = R;
          } else if (t.listenerCount("redirect") === 0) {
            let u = l ? t._originalIpc ? n.socketPath === t._originalHostOrSocketPath : false : t._originalIpc ? false : i.host === t._originalHostOrSocketPath;
            (!u || t._originalSecure && !o) && (delete n.headers.authorization, delete n.headers.cookie, u || delete n.headers.host, n.auth = void 0);
          }
          n.auth && !r.headers.authorization && (r.headers.authorization = "Basic " + Buffer.from(n.auth).toString("base64")), m = t._req = h(n), t._redirects && t.emit("redirect", t.url, m);
        } else
          m = t._req = h(n);
        n.timeout && m.on("timeout", () => {
          w(t, m, "Opening handshake has timed out");
        }), m.on("error", (u) => {
          m === null || m[Mt] || (m = t._req = null, be(t, u));
        }), m.on("response", (u) => {
          let y = u.headers.location, R = u.statusCode;
          if (y && n.followRedirects && R >= 300 && R < 400) {
            if (++t._redirects > n.maxRedirects) {
              w(t, m, "Maximum redirects exceeded");
              return;
            }
            m.abort();
            let d;
            try {
              d = new Ve(y, e);
            } catch {
              let q = new SyntaxError(`Invalid URL: ${y}`);
              be(t, q);
              return;
            }
            Dt(t, d, s, r);
          } else
            t.emit("unexpected-response", m, u) || w(t, m, `Unexpected server response: ${u.statusCode}`);
        }), m.on("upgrade", (u, y, R) => {
          if (t.emit("upgrade", u), t.readyState !== g.CONNECTING)
            return;
          m = t._req = null;
          let d = u.headers.upgrade;
          if (d === void 0 || d.toLowerCase() !== "websocket") {
            w(t, y, "Invalid Upgrade header");
            return;
          }
          let Ce = tr("sha1").update(c + or).digest("base64");
          if (u.headers["sec-websocket-accept"] !== Ce) {
            w(t, y, "Invalid Sec-WebSocket-Accept header");
            return;
          }
          let q = u.headers["sec-websocket-protocol"], C;
          if (q !== void 0 ? p.size ? p.has(q) || (C = "Server sent an invalid subprotocol") : C = "Server sent a subprotocol but none was requested" : p.size && (C = "Server sent no subprotocol"), C) {
            w(t, y, C);
            return;
          }
          q && (t._protocol = q);
          let E = u.headers["sec-websocket-extensions"];
          if (E !== void 0) {
            if (!_) {
              w(t, y, "Server sent a Sec-WebSocket-Extensions header but no extension was requested");
              return;
            }
            let x;
            try {
              x = ur(E);
            } catch {
              w(t, y, "Invalid Sec-WebSocket-Extensions header");
              return;
            }
            let H = Object.keys(x);
            if (H.length !== 1 || H[0] !== D.extensionName) {
              w(t, y, "Server indicated an extension that was not requested");
              return;
            }
            try {
              _.accept(x[D.extensionName]);
            } catch {
              w(t, y, "Invalid Sec-WebSocket-Extensions header");
              return;
            }
            t._extensions[D.extensionName] = _;
          }
          t.setSocket(y, R, { allowSynchronousEvents: n.allowSynchronousEvents, generateMask: n.generateMask, maxBufferedChunks: n.maxBufferedChunks, maxFragments: n.maxFragments, maxPayload: n.maxPayload, skipUTF8Validation: n.skipUTF8Validation });
        }), n.finishRequest ? n.finishRequest(m, t) : m.end();
      }
      function be(t, e) {
        t._readyState = g.CLOSING, t._errorEmitted = true, t.emit("error", e), t.emitClose();
      }
      function gr(t) {
        return t.path = t.socketPath, It.connect(t);
      }
      function _r(t) {
        return t.path = void 0, !t.servername && t.servername !== "" && (t.servername = It.isIP(t.host) ? "" : t.host), Qs.connect(t);
      }
      function w(t, e, s) {
        t._readyState = g.CLOSING;
        let r = new Error(s);
        Error.captureStackTrace(r, w), e.setHeader ? (e[Mt] = true, e.abort(), e.socket && !e.socket.destroyed && e.socket.destroy(), process.nextTick(be, t, r)) : (e.destroy(r), e.once("error", t.emit.bind(t, "error")), e.once("close", t.emitClose.bind(t)));
      }
      function Ye(t, e, s) {
        if (e) {
          let r = nr(e) ? e.size : dr(e).length;
          t._socket ? t._sender._bufferedBytes += r : t._bufferedAmount += r;
        }
        if (s) {
          let r = new Error(`WebSocket is not open: readyState ${t.readyState} (${I[t.readyState]})`);
          process.nextTick(s, r);
        }
      }
      function mr(t, e) {
        let s = this[S];
        s._closeFrameReceived = true, s._closeMessage = e, s._closeCode = t, s._socket[S] !== void 0 && (s._socket.removeListener("data", we), process.nextTick(Ut, s._socket), t === 1005 ? s.close() : s.close(t, e));
      }
      function yr() {
        let t = this[S];
        t.isPaused || t._socket.resume();
      }
      function Sr(t) {
        let e = this[S];
        e._socket[S] !== void 0 && (e._socket.removeListener("data", we), process.nextTick(Ut, e._socket), e.close(t[lr])), e._errorEmitted || (e._errorEmitted = true, e.emit("error", t));
      }
      function Bt() {
        this[S].emitClose();
      }
      function Er(t, e) {
        this[S].emit("message", t, e);
      }
      function xr(t) {
        let e = this[S];
        e._autoPong && e.pong(t, !this._isServer, Rt), e.emit("ping", t);
      }
      function br(t) {
        this[S].emit("pong", t);
      }
      function Ut(t) {
        t.resume();
      }
      function wr(t) {
        let e = this[S];
        e.readyState !== g.CLOSED && (e.readyState === g.OPEN && (e._readyState = g.CLOSING, Ft(e)), this._socket.end(), e._errorEmitted || (e._errorEmitted = true, e.emit("error", t)));
      }
      function Ft(t) {
        t._closeTimer = setTimeout(t._socket.destroy.bind(t._socket), t._closeTimeout);
      }
      function qt() {
        let t = this[S];
        if (this.removeListener("close", qt), this.removeListener("data", we), this.removeListener("end", Wt), t._readyState = g.CLOSING, !this._readableState.endEmitted && !t._closeFrameReceived && !t._receiver._writableState.errorEmitted && this._readableState.length !== 0) {
          let e = this.read(this._readableState.length);
          t._receiver.write(e);
        }
        t._receiver.end(), this[S] = void 0, clearTimeout(t._closeTimer), t._receiver._writableState.finished || t._receiver._writableState.errorEmitted ? t.emitClose() : (t._receiver.on("error", Bt), t._receiver.on("finish", Bt));
      }
      function we(t) {
        this[S]._receiver.write(t) || this.pause();
      }
      function Wt() {
        let t = this[S];
        t._readyState = g.CLOSING, t._receiver.end(), this.end();
      }
      function $t() {
        let t = this[S];
        this.removeListener("error", $t), this.on("error", Rt), t && (t._readyState = g.CLOSING, this.destroy());
      }
    });
    var Ht = b((Cn, zt) => {
      "use strict";
      var Ln = Te(), { Duplex: Tr } = require("stream");
      function Gt(t) {
        t.emit("close");
      }
      function vr() {
        !this.destroyed && this._writableState.finished && this.destroy();
      }
      function Vt(t) {
        this.removeListener("error", Vt), this.destroy(), this.listenerCount("error") === 0 && this.emit("error", t);
      }
      function kr(t, e) {
        let s = true, r = new Tr({ ...e, autoDestroy: false, emitClose: false, objectMode: false, writableObjectMode: false });
        return t.on("message", function(i, o) {
          let l = !o && r._readableState.objectMode ? i.toString() : i;
          r.push(l) || t.pause();
        }), t.once("error", function(i) {
          r.destroyed || (s = false, r.destroy(i));
        }), t.once("close", function() {
          r.destroyed || r.push(null);
        }), r._destroy = function(n, i) {
          if (t.readyState === t.CLOSED) {
            i(n), process.nextTick(Gt, r);
            return;
          }
          let o = false;
          t.once("error", function(f) {
            o = true, i(f);
          }), t.once("close", function() {
            o || i(n), process.nextTick(Gt, r);
          }), s && t.terminate();
        }, r._final = function(n) {
          if (t.readyState === t.CONNECTING) {
            t.once("open", function() {
              r._final(n);
            });
            return;
          }
          t._socket !== null && (t._socket._writableState.finished ? (n(), r._readableState.endEmitted && r.destroy()) : (t._socket.once("finish", function() {
            n();
          }), t.close()));
        }, r._read = function() {
          t.isPaused && t.resume();
        }, r._write = function(n, i, o) {
          if (t.readyState === t.CONNECTING) {
            t.once("open", function() {
              r._write(n, i, o);
            });
            return;
          }
          t.send(n, o);
        }, r.on("end", vr), r.on("error", Vt), r;
      }
      zt.exports = kr;
    });
    var Ke = b((Pn, Yt) => {
      "use strict";
      var { tokenChars: Or } = Z();
      function Lr(t) {
        let e = /* @__PURE__ */ new Set(), s = -1, r = -1, n = 0;
        for (n; n < t.length; n++) {
          let o = t.charCodeAt(n);
          if (r === -1 && Or[o] === 1)
            s === -1 && (s = n);
          else if (n !== 0 && (o === 32 || o === 9))
            r === -1 && s !== -1 && (r = n);
          else if (o === 44) {
            if (s === -1)
              throw new SyntaxError(`Unexpected character at index ${n}`);
            r === -1 && (r = n);
            let l = t.slice(s, r);
            if (e.has(l))
              throw new SyntaxError(`The "${l}" subprotocol is duplicated`);
            e.add(l), s = r = -1;
          } else
            throw new SyntaxError(`Unexpected character at index ${n}`);
        }
        if (s === -1 || r !== -1)
          throw new SyntaxError("Unexpected end of input");
        let i = t.slice(s, n);
        if (e.has(i))
          throw new SyntaxError(`The "${i}" subprotocol is duplicated`);
        return e.add(i), e;
      }
      Yt.exports = { parse: Lr };
    });
    var ts = b((An, es) => {
      "use strict";
      var Cr = require("events"), ve = require("http"), { Duplex: Nn } = require("stream"), { createHash: Pr } = require("crypto"), Kt = Ee(), G = J(), Nr = Ke(), Ar = Te(), { CLOSE_TIMEOUT: Br, GUID: Ir, kWebSocket: Rr } = N(), Mr = /^[+/0-9A-Za-z]{22}==$/, Xt = 0, Jt = 1, Qt = 2, Xe = class extends Cr {
        constructor(e, s) {
          if (super(), e = { allowSynchronousEvents: true, autoPong: true, maxBufferedChunks: 256 * 1024, maxFragments: 16 * 1024, maxPayload: 100 * 1024 * 1024, skipUTF8Validation: false, perMessageDeflate: false, handleProtocols: null, clientTracking: true, closeTimeout: Br, verifyClient: null, noServer: false, backlog: null, server: null, host: null, path: null, port: null, WebSocket: Ar, ...e }, e.port == null && !e.server && !e.noServer || e.port != null && (e.server || e.noServer) || e.server && e.noServer)
            throw new TypeError('One and only one of the "port", "server", or "noServer" options must be specified');
          if (e.port != null ? (this._server = ve.createServer((r, n) => {
            let i = ve.STATUS_CODES[426];
            n.writeHead(426, { "Content-Length": i.length, "Content-Type": "text/plain" }), n.end(i);
          }), this._server.listen(e.port, e.host, e.backlog, s)) : e.server && (this._server = e.server), this._server) {
            let r = this.emit.bind(this, "connection");
            this._removeListeners = Dr(this._server, { listening: this.emit.bind(this, "listening"), error: this.emit.bind(this, "error"), upgrade: (n, i, o) => {
              this.handleUpgrade(n, i, o, r);
            } });
          }
          e.perMessageDeflate === true && (e.perMessageDeflate = {}), e.clientTracking && (this.clients = /* @__PURE__ */ new Set(), this._shouldEmitClose = false), this.options = e, this._state = Xt;
        }
        address() {
          if (this.options.noServer)
            throw new Error('The server is operating in "noServer" mode');
          return this._server ? this._server.address() : null;
        }
        close(e) {
          if (this._state === Qt) {
            e && this.once("close", () => {
              e(new Error("The server is not running"));
            }), process.nextTick(fe, this);
            return;
          }
          if (e && this.once("close", e), this._state !== Jt)
            if (this._state = Jt, this.options.noServer || this.options.server)
              this._server && (this._removeListeners(), this._removeListeners = this._server = null), this.clients ? this.clients.size ? this._shouldEmitClose = true : process.nextTick(fe, this) : process.nextTick(fe, this);
            else {
              let s = this._server;
              this._removeListeners(), this._removeListeners = this._server = null, s.close(() => {
                fe(this);
              });
            }
        }
        shouldHandle(e) {
          if (this.options.path) {
            let s = e.url.indexOf("?");
            if ((s !== -1 ? e.url.slice(0, s) : e.url) !== this.options.path)
              return false;
          }
          return true;
        }
        handleUpgrade(e, s, r, n) {
          s.on("error", Zt);
          let i = e.headers["sec-websocket-key"], o = e.headers.upgrade, l = +e.headers["sec-websocket-version"];
          if (e.method !== "GET") {
            V(this, e, s, 405, "Invalid HTTP method");
            return;
          }
          if (o === void 0 || o.toLowerCase() !== "websocket") {
            V(this, e, s, 400, "Invalid Upgrade header");
            return;
          }
          if (i === void 0 || !Mr.test(i)) {
            V(this, e, s, 400, "Missing or invalid Sec-WebSocket-Key header");
            return;
          }
          if (l !== 13 && l !== 8) {
            V(this, e, s, 400, "Missing or invalid Sec-WebSocket-Version header", { "Sec-WebSocket-Version": "13, 8" });
            return;
          }
          if (!this.shouldHandle(e)) {
            ce(s, 400);
            return;
          }
          let f = e.headers["sec-websocket-protocol"], a = /* @__PURE__ */ new Set();
          if (f !== void 0)
            try {
              a = Nr.parse(f);
            } catch {
              V(this, e, s, 400, "Invalid Sec-WebSocket-Protocol header");
              return;
            }
          let c = e.headers["sec-websocket-extensions"], h = {};
          if (this.options.perMessageDeflate && c !== void 0) {
            let p = new G({ ...this.options.perMessageDeflate, isServer: true, maxPayload: this.options.maxPayload });
            try {
              let _ = Kt.parse(c);
              _[G.extensionName] && (p.accept(_[G.extensionName]), h[G.extensionName] = p);
            } catch {
              V(this, e, s, 400, "Invalid or unacceptable Sec-WebSocket-Extensions header");
              return;
            }
          }
          if (this.options.verifyClient) {
            let p = { origin: e.headers[`${l === 8 ? "sec-websocket-origin" : "origin"}`], secure: !!(e.socket.authorized || e.socket.encrypted), req: e };
            if (this.options.verifyClient.length === 2) {
              this.options.verifyClient(p, (_, m, u, y) => {
                if (!_)
                  return ce(s, m || 401, u, y);
                this.completeUpgrade(h, i, a, e, s, r, n);
              });
              return;
            }
            if (!this.options.verifyClient(p))
              return ce(s, 401);
          }
          this.completeUpgrade(h, i, a, e, s, r, n);
        }
        completeUpgrade(e, s, r, n, i, o, l) {
          if (!i.readable || !i.writable)
            return i.destroy();
          if (i[Rr])
            throw new Error("server.handleUpgrade() was called more than once with the same socket, possibly due to a misconfiguration");
          if (this._state > Xt)
            return ce(i, 503);
          let a = ["HTTP/1.1 101 Switching Protocols", "Upgrade: websocket", "Connection: Upgrade", `Sec-WebSocket-Accept: ${Pr("sha1").update(s + Ir).digest("base64")}`], c = new this.options.WebSocket(null, void 0, this.options);
          if (r.size) {
            let h = this.options.handleProtocols ? this.options.handleProtocols(r, n) : r.values().next().value;
            h && (a.push(`Sec-WebSocket-Protocol: ${h}`), c._protocol = h);
          }
          if (e[G.extensionName]) {
            let h = e[G.extensionName].params, p = Kt.format({ [G.extensionName]: [h] });
            a.push(`Sec-WebSocket-Extensions: ${p}`), c._extensions = e;
          }
          this.emit("headers", a, n), i.write(a.concat(`\r
`).join(`\r
`)), i.removeListener("error", Zt), c.setSocket(i, o, { allowSynchronousEvents: this.options.allowSynchronousEvents, maxBufferedChunks: this.options.maxBufferedChunks, maxFragments: this.options.maxFragments, maxPayload: this.options.maxPayload, skipUTF8Validation: this.options.skipUTF8Validation }), this.clients && (this.clients.add(c), c.on("close", () => {
            this.clients.delete(c), this._shouldEmitClose && !this.clients.size && process.nextTick(fe, this);
          })), l(c, n);
        }
      };
      es.exports = Xe;
      function Dr(t, e) {
        for (let s of Object.keys(e))
          t.on(s, e[s]);
        return function() {
          for (let r of Object.keys(e))
            t.removeListener(r, e[r]);
        };
      }
      function fe(t) {
        t._state = Qt, t.emit("close");
      }
      function Zt() {
        this.destroy();
      }
      function ce(t, e, s, r) {
        s = s || ve.STATUS_CODES[e], r = { Connection: "close", "Content-Type": "text/html", "Content-Length": Buffer.byteLength(s), ...r }, t.once("finish", t.destroy), t.end(`HTTP/1.1 ${e} ${ve.STATUS_CODES[e]}\r
` + Object.keys(r).map((n) => `${n}: ${r[n]}`).join(`\r
`) + `\r
\r
` + s);
      }
      function V(t, e, s, r, n, i) {
        if (t.listenerCount("wsClientError")) {
          let o = new Error(n);
          Error.captureStackTrace(o, V), t.emit("wsClientError", o, s, e);
        } else
          ce(s, r, n, i);
      }
    });
    var dn = {};
    _s(dn, { PagesAI: () => Le, buildApiMeta: () => on });
    module.exports = ms(dn);
    var Ur = P(Ht(), 1), Fr = P(Ee(), 1), qr = P(J(), 1), Wr = P(qe(), 1), $r = P(je(), 1), jr = P(Ke(), 1), ss = P(Te(), 1), Gr = P(ts(), 1);
    var rs = ss.default;
    var Vr = "https://pages-api.cloud.tencent.com", zr = "https://pages-api.edgeone.ai", Hr = [Vr, zr], ke = "/v1", Oe = class {
      baseUrl;
      baseSelectionPromise;
      apiToken;
      defaultEngineModelType;
      defaultTtsVoiceId;
      appId;
      requestMeta;
      baseCandidates;
      debugLog;
      constructor(e) {
        if (!e.apiToken)
          throw new Error("PAGES_API_TOKEN is required");
        this.baseUrl = null, this.baseSelectionPromise = null, this.apiToken = e.apiToken.trim(), this.defaultEngineModelType = e.defaultEngineModelType, this.defaultTtsVoiceId = e.defaultTtsVoiceId, this.appId = e.appId, this.requestMeta = e.requestMeta || {}, this.baseCandidates = Xr(e.baseUrls), this.debugLog = typeof e.debugLog == "function" ? e.debugLog : null;
      }
      async signAsr(e = {}) {
        var _a2;
        let s = await this.request(ke, { Action: "SignPagesAiAsr", EngineModelType: e.engineModelType || this.defaultEngineModelType, VoiceId: e.voiceId, ApiToken: this.apiToken, ...this.requestMeta, ...this.appId !== void 0 ? { AppId: this.appId } : {} });
        if (!((_a2 = s == null ? void 0 : s.Asr) == null ? void 0 : _a2.websocketUrl)) {
          let r = is(s);
          throw new Error(`ASR signature response is invalid${r ? `: ${r}` : ""}`);
        }
        return s.Asr;
      }
      async signTts(e, s = {}) {
        var _a2, _b, _c;
        let r = (e || "").trim();
        if (!r)
          throw new Error("TTS text is empty");
        let n = await this.request(ke, { Action: "SignPagesAiTts", ApiToken: this.apiToken, VoiceId: s.voiceId || this.defaultTtsVoiceId, Text: r, ...this.requestMeta, ...this.appId !== void 0 ? { AppId: this.appId } : {} });
        if (!((_a2 = n.Tts) == null ? void 0 : _a2.headers) || !((_b = n.Tts) == null ? void 0 : _b.endpoint) || !((_c = n.Tts) == null ? void 0 : _c.payload)) {
          let i = is(n);
          throw new Error(`TTS signature response is invalid${i ? `: ${i}` : ""}`);
        }
        return n.Tts;
      }
      async completeLlm(e) {
        var _a2;
        let r = (_a2 = await this.callLlmEndpoint({ ApiToken: this.apiToken, ...this.requestMeta, ...this.appId !== void 0 ? { AppId: this.appId } : {}, Messages: e })) == null ? void 0 : _a2.Content;
        if (typeof r != "string" || !r.trim())
          throw new Error("LLM response missing content");
        return r;
      }
      async callLlmEndpoint(e) {
        return this.request(ke, { ...e, Action: "CompletePagesAiLlm" });
      }
      async request(e, s) {
        let r = await this.ensureBaseUrl(), n = new URL(e, r), i;
        U(this.debugLog, "pages-ai:http:request", { url: n.toString(), payload: s, headers: { "Content-Type": "application/json", Authorization: Jr(`Bearer ${this.apiToken}`) } });
        try {
          i = await fetch(n.toString(), { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${this.apiToken}` }, body: JSON.stringify(s) });
        } catch (a) {
          throw U(this.debugLog, "pages-ai:http:error", { url: n.toString(), error: (a == null ? void 0 : a.message) || String(a) }), new Error((a == null ? void 0 : a.message) || String(a));
        }
        let o = await i.text();
        U(this.debugLog, "pages-ai:http:response", { url: n.toString(), status: i.status, statusText: i.statusText, headers: os(i.headers), body: o });
        let l = {};
        try {
          l = o ? JSON.parse(o) : {};
        } catch {
          l = {};
        }
        let f = Yr(l);
        if (!i.ok) {
          let a = Kr(f) || i.statusText || "Request failed";
          throw new Error(`[${i.status}] ${a}`);
        }
        return f || {};
      }
      async ensureBaseUrl() {
        if (this.baseUrl)
          return this.baseUrl;
        if (this.baseSelectionPromise)
          return this.baseSelectionPromise;
        this.baseSelectionPromise = this.detectBaseUrl();
        try {
          let e = await this.baseSelectionPromise;
          return this.baseUrl = e, e;
        } finally {
          this.baseSelectionPromise = null;
        }
      }
      async detectBaseUrl() {
        U(this.debugLog, "pages-ai:http:detect-base", { candidates: this.baseCandidates });
        let e = await Promise.all(this.baseCandidates.map((n) => this.probeBase(n))), s = e.find((n) => n.ok);
        if (U(this.debugLog, "pages-ai:http:detect-base:result", { probes: e, winner: (s == null ? void 0 : s.base) || null }), s == null ? void 0 : s.base)
          return s.base;
        let r = e.map((n) => `${n.base}: ${n.reason || "Unknown error"}`).join("; ");
        throw new Error(`All endpoints failed: ${r}`);
      }
      async probeBase(e) {
        let s = new URL(ke, e);
        U(this.debugLog, "pages-ai:http:probe:request", { base: e, url: s.toString() });
        try {
          let r = await fetch(s.toString(), { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${this.apiToken}` }, body: JSON.stringify({ Action: "TokenPing" }) }), n = await r.text();
          U(this.debugLog, "pages-ai:http:probe:response", { base: e, status: r.status, statusText: r.statusText, headers: os(r.headers), body: n });
          let i = {};
          try {
            i = n ? JSON.parse(n) : {};
          } catch {
            i = {};
          }
          if (!r.ok)
            return { base: e, ok: false, reason: `[${r.status}] ${r.statusText || "Request failed"}` };
          let o = (i == null ? void 0 : i.Code) ?? (i == null ? void 0 : i.code), l = (i == null ? void 0 : i.Message) ?? (i == null ? void 0 : i.message) ?? "";
          if (o === 109 || typeof l == "string" && l.toLowerCase().includes("region")) {
            let a = [o, l].filter(Boolean).join(": ");
            return { base: e, ok: false, reason: a || "Token not allowed for this region" };
          }
          return { base: e, ok: true };
        } catch (r) {
          return U(this.debugLog, "pages-ai:http:probe:error", { base: e, url: s.toString(), error: (r == null ? void 0 : r.message) || String(r) }), { base: e, ok: false, reason: (r == null ? void 0 : r.message) || String(r) };
        }
      }
    };
    function ns(t) {
      let e = (t || "").trim(), s = e && /^[a-z]+:\/\//i.test(e) ? e : `https://${e}`;
      return s.endsWith("/") ? s : `${s}/`;
    }
    function Yr(t) {
      if (t && typeof t == "object") {
        if (t.Data && typeof t.Data == "object")
          return t.Data.Response && typeof t.Data.Response == "object" ? t.Data.Response : t.Data;
        if (t.Response && typeof t.Response == "object")
          return t.Response;
      }
      return t || {};
    }
    function Kr(t) {
      if (!t || typeof t != "object")
        return "";
      let e = t.Error || t.error;
      return (e == null ? void 0 : e.Message) ? e.Message : typeof e == "string" ? e : t.message || t.Message || "";
    }
    function is(t) {
      try {
        return JSON.stringify(t);
      } catch {
        return "";
      }
    }
    function Xr(t) {
      let e = Hr.map(ns), s = (t || []).map(ns).filter((i) => !!i), r = /* @__PURE__ */ new Set(), n = [];
      return [...s, ...e].forEach((i) => {
        !i || r.has(i) || (r.add(i), n.push(i));
      }), n.length ? n : e;
    }
    function U(t, e, s) {
      if (t)
        try {
          t(e, s);
        } catch {
        }
    }
    function Jr(t) {
      if (!t)
        return t;
      let e = Math.min(6, Math.floor(t.length / 3));
      return `${t.slice(0, e)}***${t.slice(-e)}`;
    }
    function os(t) {
      if (!t)
        return {};
      if (typeof t.entries == "function")
        return Array.from(t.entries()).reduce((r, [n, i]) => (r[n] = i, r), {});
      let e = {};
      return Object.entries(t).forEach(([s, r]) => {
        e[s.toLowerCase()] = r;
      }), e;
    }
    var Je = P(require("https")), Zr = Je.default.request.bind(Je.default);
    function as(t, e = {}, s = null) {
      let { endpoint: r, payload: n, headers: i } = t;
      if (!n)
        throw new Error("TTS payload missing");
      let { signal: o } = e;
      if (o == null ? void 0 : o.aborted)
        throw new Error("Aborted");
      let l = { ...i, "Content-Length": (i == null ? void 0 : i["Content-Length"]) ?? Buffer.byteLength(n) };
      F(s, "pages-ai:tts:sse:request", { endpoint: r, headers: l, payload: n });
      let f = null, a = false, c = null, h = [], p = null, _ = () => {
        p && (p(), p = null);
      }, m = (d) => {
        a || (h.push(d), _());
      }, u = () => {
        a || (a = true, _());
      }, y = (d) => {
        a || (c = d instanceof Error ? d : new Error(String(d)), a = true, _());
      }, R = { async next() {
        if (h.length)
          return { value: h.shift(), done: false };
        if (c)
          throw c;
        if (a)
          return { value: void 0, done: true };
        if (await new Promise((d) => {
          p = d;
        }), h.length)
          return { value: h.shift(), done: false };
        if (c)
          throw c;
        return { value: void 0, done: true };
      }, async return() {
        if (u(), f)
          try {
            f.destroy();
          } catch {
          }
        return { value: void 0, done: true };
      }, [Symbol.asyncIterator]() {
        return this;
      } };
      return f = Zr({ hostname: r, port: 443, path: "/", method: "POST", signal: o, headers: l }, (d) => {
        if (F(s, "pages-ai:tts:sse:response", { endpoint: r, statusCode: d.statusCode, statusMessage: d.statusMessage, headers: d.headers }), !(d.headers["content-type"] || "").toLowerCase().includes("text/event-stream")) {
          let E = "";
          d.on("data", (x) => {
            E += x.toString();
          }), d.on("end", () => {
            var _a2, _b;
            let x = `TTS request failed with status ${d.statusCode ?? ""}`.trim();
            if (E)
              try {
                let k = (_b = (_a2 = JSON.parse(E)) == null ? void 0 : _a2.Response) == null ? void 0 : _b.Error;
                (k == null ? void 0 : k.Message) ? x = `${k.Code || "Error"}: ${k.Message}` : x = `${x}: ${E.slice(0, 200)}`;
              } catch {
                x = `${x}: ${E.slice(0, 200)}`;
              }
            F(s, "pages-ai:tts:sse:error-response", { endpoint: r, statusCode: d.statusCode, statusMessage: d.statusMessage, headers: d.headers, body: E }), y(new Error(x));
          }), d.on("error", y);
          return;
        }
        let C = "";
        d.on("data", (E) => {
          C += E.toString();
          let x = C.split(`
`);
          C = x.pop() || "";
          for (let H of x)
            if (H.startsWith("data:")) {
              let k = H.slice(5).trim();
              if (k)
                try {
                  m({ data: k }), F(s, "pages-ai:tts:sse:event", { endpoint: r, data: Qr(k) });
                } catch (Y) {
                  let cs = Y instanceof Error ? Y.message : String(Y);
                  console.error("\u89E3\u6790 SSE \u6570\u636E\u5931\u8D25:", cs);
                }
            }
        }), d.on("end", () => {
          F(s, "pages-ai:tts:sse:end", { endpoint: r }), u();
        }), d.on("error", (E) => {
          F(s, "pages-ai:tts:sse:error", { endpoint: r, message: E instanceof Error ? E.message : String(E) }), y(E);
        });
      }), f.on("error", (d) => {
        F(s, "pages-ai:tts:sse:request-error", { endpoint: r, message: d instanceof Error ? d.message : String(d) }), y(d);
      }), o && o.addEventListener("abort", () => {
        F(s, "pages-ai:tts:sse:aborted", { endpoint: r }), y(new Error("Aborted")), f == null ? void 0 : f.destroy(new Error("Aborted"));
      }, { once: true }), f.write(n), f.end(), R;
    }
    function F(t, e, s) {
      if (t)
        try {
          t(e, s);
        } catch {
        }
    }
    function Qr(t) {
      return !t || t.length <= 200 ? t : { preview: t.slice(0, 200), length: t.length };
    }
    var en = 251195406, tn = "16k_zh_en", sn = void 0, rn = ["https://pages-api.cloud.tencent.com", "https://pages-api.edgeone.ai"], ls = { Version: "2022-09-01", Region: "ch", Language: "zh", RequestId: "111", ClientIp: "1.1.1.1", ApiModule: "teo", RequestSource: "API", CamContext: "hall", AccountArea: "0", Uin: "100000043181", SubAccountUin: "100000043181", Timestamp: "111" }, fs = false, Le = (_a = class {
      constructor(e) {
        __publicField(this, "asr");
        __publicField(this, "llm");
        __publicField(this, "tts");
        __privateAdd(this, _e, void 0);
        __privateAdd(this, _t, void 0);
        if (!(e == null ? void 0 : e.apiToken))
          throw new Error("apiToken is required to initialize PagesAI");
        let s = nn(e), r = cn(s.debugLogger);
        __privateSet(this, _t, r), __privateSet(this, _e, new Oe({ apiToken: s.apiToken, defaultEngineModelType: s.engineModelType, defaultTtsVoiceId: s.ttsVoiceId, appId: s.appId, baseUrls: s.apiBaseUrls, requestMeta: s.apiMeta, debugLog: r })), this.asr = re(an(__privateGet(this, _e), r)), this.llm = re(ln(__privateGet(this, _e), r)), this.tts = re(fn(__privateGet(this, _e), r)), re(this);
      }
    }, _e = new WeakMap(), _t = new WeakMap(), _a);
    function nn(t) {
      return { apiToken: t.apiToken, engineModelType: tn, ttsVoiceId: sn, appId: en, apiBaseUrls: rn, apiMeta: ls, debugLogger: fs ? t.debugLogger : null };
    }
    function on() {
      return { ...ls };
    }
    function an(t, e) {
      return { async createSocket() {
        try {
          let s = await t.signAsr();
          z(e, "pages-ai:asr:sign", s);
          let r = new rs(s.websocketUrl, { perMessageDeflate: false, headers: s.headers });
          return r.on("open", () => z(e, "pages-ai:asr:socket:open", { url: s.websocketUrl })), r.on("close", (n, i) => {
            var _a2;
            return z(e, "pages-ai:asr:socket:close", { url: s.websocketUrl, code: n, reason: (_a2 = i == null ? void 0 : i.toString) == null ? void 0 : _a2.call(i) });
          }), r.on("error", (n) => z(e, "pages-ai:asr:socket:error", { url: s.websocketUrl, message: (n == null ? void 0 : n.message) || String(n) })), r.on("message", (n) => z(e, "pages-ai:asr:socket:message", { url: s.websocketUrl, message: hn(n) })), re({ socket: r, engineModelType: s.engineModelType, voiceId: s.voiceId });
        } catch (s) {
          let r = s instanceof Error ? s.message : String(s);
          throw new Error(`ASR runtime not configured: ${r}`);
        }
      } };
    }
    function ln(t, e) {
      return { async complete(s) {
        if (!Array.isArray(s) || !s.length)
          throw new Error("LLM messages are empty");
        return z(e, "pages-ai:llm:complete", { messages: s }), t.completeLlm(s);
      } };
    }
    function fn(t, e) {
      return { async synthesize(s, r = {}) {
        let n = (s || "").trim();
        if (!n)
          throw new Error("TTS text is empty");
        z(e, "pages-ai:tts:synthesize", { text: n });
        let i = await t.signTts(n);
        return as(i, { signal: r == null ? void 0 : r.signal }, e);
      } };
    }
    function re(t) {
      if (!t || typeof t != "object" || Object.isFrozen(t))
        return t;
      let e = Object.getPrototypeOf(t);
      return !(e === Object.prototype || e === null) && !Array.isArray(t) || (Object.freeze(t), Object.getOwnPropertyNames(t).forEach((r) => {
        let n = t[r];
        n && typeof n == "object" && !Object.isFrozen(n) && re(n);
      })), t;
    }
    function cn(t) {
      return fs && typeof t == "function" ? (e, s) => {
        try {
          t(e, s);
        } catch {
        }
      } : null;
    }
    function z(t, e, s) {
      t && t(e, s);
    }
    function hn(t) {
      return t == null || typeof t == "string" ? t : Buffer.isBuffer(t) ? { type: "buffer", length: t.length, preview: t.toString("utf8", 0, Math.min(128, t.length)) } : typeof t.toString == "function" ? t.toString() : t;
    }
    function un() {
      if (typeof globalThis > "u")
        return;
      let t = globalThis;
      t.PagesAI || Object.defineProperty(t, "PagesAI", { configurable: false, enumerable: false, writable: false, value: Le });
    }
    un();
  }
});
export default require_stdin();

var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
}) : x)(function(x) {
  if (typeof require !== "undefined")
    return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x + '" is not supported');
});

// <stdin>
import http from "http";
(async function() {
  var kvModule = { exports: {} };
  (function(module, exports) {
    var O = Object.create;
    var v = Object.defineProperty;
    var Y = Object.getOwnPropertyDescriptor;
    var F = Object.getOwnPropertyNames;
    var Z = Object.getPrototypeOf, X = Object.prototype.hasOwnProperty;
    var J = (r, e) => {
      for (var t in e)
        v(r, t, { get: e[t], enumerable: true });
    }, x = (r, e, t, n) => {
      if (e && typeof e == "object" || typeof e == "function")
        for (let o of F(e))
          !X.call(r, o) && o !== t && v(r, o, { get: () => e[o], enumerable: !(n = Y(e, o)) || n.enumerable });
      return r;
    };
    var W = (r, e, t) => (t = r != null ? O(Z(r)) : {}, x(e || !r || !r.__esModule ? v(t, "default", { value: r, enumerable: true }) : t, r)), q = (r) => x(v({}, "__esModule", { value: true }), r);
    var ne = {};
    J(ne, { bootstrap: () => re, createKVClient: () => S, getConfigs: () => M, initKVBindings: () => z });
    module.exports = q(ne);
    var k = W(__require("net"));
    var K = class {
      static encodeCommand(e) {
        let t = [];
        t.push(`*${e.length}\r
`);
        for (let n of e) {
          let o = Buffer.byteLength(n, "utf8");
          t.push("$" + o + `\r
` + n + `\r
`);
        }
        return t.join("");
      }
      static encodeCommandBuffer(e) {
        let t = [];
        t.push(Buffer.from(`*${e.length}\r
`));
        for (let n of e) {
          let o = typeof n == "string" ? Buffer.from(n, "utf8") : n;
          t.push(Buffer.from("$" + o.length + `\r
`)), t.push(o), t.push(Buffer.from(`\r
`));
        }
        return Buffer.concat(t);
      }
    }, w = class {
      buffer = "";
      append(e) {
        Buffer.isBuffer(e) ? this.buffer += e.toString("utf8") : this.buffer += e;
      }
      get bufferLength() {
        return this.buffer.length;
      }
      clear() {
        this.buffer = "";
      }
      parse() {
        var o;
        if (this.buffer.length === 0)
          return null;
        let e = this.buffer[0], t = this.buffer.indexOf(`\r
`);
        if (t === -1)
          return null;
        let n = this.buffer.substring(1, t);
        switch (e) {
          case "+":
            return this.buffer = this.buffer.substring(t + 2), { type: "simple_string", value: n };
          case "-":
            return this.buffer = this.buffer.substring(t + 2), { type: "error", value: n };
          case ":":
            return this.buffer = this.buffer.substring(t + 2), { type: "integer", value: parseInt(n, 10) };
          case "$":
            return this.parseBulkString(n, t);
          case "*":
            return this.parseArray(n, t);
          default: {
            let f = e.charCodeAt(0), a = this.buffer.substring(0, 100).replace(/\r/g, "\\r").replace(/\n/g, "\\n").replace(/\t/g, "\\t"), u = ((o = Buffer.from(this.buffer.substring(0, 20)).toString("hex").match(/.{1,2}/g)) == null ? void 0 : o.join(" ")) || "";
            throw new Error(`Unknown RESP type: '${e}' (char code: ${f}, hex: 0x${f.toString(16)})
Buffer length: ${this.buffer.length}
Buffer preview (first 100 chars): ${a}
Buffer hex (first 20 bytes): ${u}`);
          }
        }
      }
      parseBulkString(e, t) {
        let n = parseInt(e, 10);
        if (n === -1)
          return this.buffer = this.buffer.substring(t + 2), { type: "null", value: null };
        let o = t + 2, f = o + n, a = f + 2;
        if (this.buffer.length < a)
          return null;
        let u = this.buffer.substring(o, f);
        return this.buffer = this.buffer.substring(a), { type: "bulk_string", value: u };
      }
      parseArray(e, t) {
        let n = parseInt(e, 10);
        if (n === -1)
          return this.buffer = this.buffer.substring(t + 2), { type: "null", value: null };
        if (n === 0)
          return this.buffer = this.buffer.substring(t + 2), { type: "array", value: [] };
        let o = this.buffer;
        this.buffer = this.buffer.substring(t + 2);
        let f = [];
        for (let a = 0; a < n; a++) {
          let u = this.parse();
          if (u === null)
            return this.buffer = o, null;
          f.push(u);
        }
        return { type: "array", value: f };
      }
    };
    var R = "EO_KV_BINDINGS";
    var A = /^[a-zA-Z0-9_]+$/;
    var V = class {
      socket = null;
      decoder = new w();
      responseQueue = [];
      host;
      port;
      timeout;
      debug;
      connected = false;
      constructor(e) {
        this.host = e.host, this.port = e.port, this.timeout = e.timeout ?? 1e4, this.debug = e.debug ?? false;
      }
      log(e, ...t) {
        this.debug && console.log(`[RespConnection] ${e}`, ...t);
      }
      connect() {
        return new Promise((e, t) => {
          this.log("Connecting to KV service..."), this.socket = k.createConnection({ host: this.host, port: this.port }), this.socket.on("connect", () => {
            this.log("TCP connection established"), this.connected = true, e();
          }), this.socket.on("data", (n) => {
            this.decoder.append(n), this.processResponses();
          }), this.socket.on("error", (n) => {
            this.log(`Socket error: ${n.message}`), t(new Error("KV connection failed"));
          }), this.socket.on("close", (n) => {
            for (this.log(`Connection closed (hadError: ${n}, pending: ${this.responseQueue.length})`), this.connected = false; this.responseQueue.length > 0; ) {
              let { reject: o } = this.responseQueue.shift();
              o(new Error("Connection closed by server"));
            }
          }), this.socket.setTimeout(this.timeout, () => {
            this.log(`Connection timeout after ${this.timeout}ms`), t(new Error("KV connection timeout"));
          });
        });
      }
      processResponses() {
        let e;
        for (; (e = this.decoder.parse()) !== null; )
          if (this.responseQueue.length > 0) {
            let { resolve: t, reject: n } = this.responseQueue.shift();
            e.type === "error" ? n(new Error(e.value)) : t(e);
          }
      }
      sendCommand(e) {
        return new Promise((t, n) => {
          if (!this.socket || !this.connected) {
            n(new Error("Not connected"));
            return;
          }
          let o = K.encodeCommand(e);
          this.log(`Sending command: ${e[0]} (${o.length} bytes)`), this.responseQueue.push({ resolve: t, reject: n }), this.socket.write(o, (f) => {
            f && this.log(`Write error: ${f.message}`);
          });
        });
      }
      close() {
        this.socket && (this.socket.end(), this.socket = null), this.connected = false;
      }
    };
    function I(r) {
      if (!r || typeof r != "string")
        throw new Error("Key must be a non-empty string");
      let e = Buffer.byteLength(r, "utf-8");
      if (e > 512)
        throw new Error(`Key size exceeds maximum limit of ${512} bytes (got ${e} bytes)`);
      if (!A.test(r))
        throw new Error("Key can only contain letters, numbers, and underscores");
    }
    function L(r) {
      if (r.length > 26214400)
        throw new Error(`Value size exceeds maximum limit of ${26214400} bytes (${Math.round(26214400 / 1024 / 1024)} MB), got ${r.length} bytes`);
    }
    async function N(r) {
      if (typeof r == "string")
        return Buffer.from(r, "utf-8");
      if (r instanceof ArrayBuffer)
        return Buffer.from(r);
      if (ArrayBuffer.isView(r))
        return Buffer.from(r.buffer, r.byteOffset, r.byteLength);
      if (typeof ReadableStream < "u" && r instanceof ReadableStream) {
        let e = [], t = r.getReader();
        try {
          for (; ; ) {
            let { done: a, value: u } = await t.read();
            if (a)
              break;
            e.push(u);
          }
        } finally {
          t.releaseLock();
        }
        let n = e.reduce((a, u) => a + u.length, 0), o = new Uint8Array(n), f = 0;
        for (let a of e)
          o.set(a, f), f += a.length;
        return Buffer.from(o);
      }
      throw new Error(`Unsupported value type: ${typeof r}`);
    }
    function U(r, e) {
      switch (e) {
        case "json":
          try {
            return JSON.parse(r.toString("utf-8"));
          } catch {
            return r.toString("utf-8");
          }
        case "arrayBuffer":
          return r.buffer.slice(r.byteOffset, r.byteOffset + r.byteLength);
        case "stream": {
          let t = r;
          return new ReadableStream({ start(n) {
            n.enqueue(new Uint8Array(t)), n.close();
          } });
        }
        case "text":
        default:
          return r.toString("utf-8");
      }
    }
    function S(r, e) {
      let t = null, n = null, o = (e == null ? void 0 : e.debug) ?? false, f = `${r.userId}@${r.userKey}`, a = `/${r.namespace}/`, u = (s, ...i) => {
        o && console.log(`[KVClient] ${s}`, ...i);
      }, m = (s) => a + s, C = (s) => s.startsWith(a) ? s.substring(a.length) : s, D = async (s) => {
        u("Authenticating...");
        let i = await s.sendCommand(["AUTH", f]);
        if (i.type === "simple_string" && i.value === "OK")
          u("Authentication successful");
        else
          throw new Error("Authentication failed");
      }, Q = async (s) => {
        u("Selecting namespace...");
        let i = await s.sendCommand(["SELECT", r.namespace]);
        if (i.type === "simple_string" && i.value === "OK")
          u("Namespace selected");
        else
          throw new Error("Namespace selection failed");
      }, b = async () => {
        if (t && !t.connected && (t = null, n = null), t && t.connected)
          return t;
        if (n) {
          if (await n, t && t.connected)
            return t;
          t = null, n = null;
        }
        let s = typeof r.servicePort == "string" ? parseInt(r.servicePort, 10) : r.servicePort;
        return t = new V({ host: r.serviceName, port: s, timeout: e == null ? void 0 : e.timeout, debug: o }), n = (async () => {
          try {
            await t.connect(), await D(t), await Q(t);
          } catch (i) {
            throw t == null || t.close(), t = null, n = null, i;
          }
        })(), await n, t;
      }, j = (s) => {
        if (s.type === "null")
          return null;
        if (s.type === "array" && Array.isArray(s.value)) {
          let i = s.value;
          if (i.length > 0) {
            let l = i[0];
            return l.type === "null" ? null : Buffer.from(l.value, "utf-8");
          }
          return null;
        }
        return s.type === "bulk_string" ? Buffer.from(s.value, "utf-8") : null;
      };
      return { async get(s, i) {
        let l = await b(), c = m(s);
        u(`GET: ${c}`);
        let h = await l.sendCommand(["oget", c]), p = j(h);
        if (p === null)
          return null;
        let g = typeof i == "string" ? i : (i == null ? void 0 : i.type) ?? "text";
        return U(p, g);
      }, async put(s, i) {
        I(s);
        let l = await b(), c = m(s), h = await N(i);
        L(h);
        let p = h.toString("utf-8");
        u(`PUT: ${c} = ${p.substring(0, 100)}${p.length > 100 ? "..." : ""}`);
        let g = ["oset", c, p], d = await l.sendCommand(g);
        if (d.type !== "simple_string" || d.value !== "OK")
          throw new Error("PUT operation failed");
      }, async delete(s) {
        let i = await b(), l = m(s);
        u(`DELETE: ${l}`);
        let c = await i.sendCommand(["odel", l]);
        if (c.type === "error")
          throw new Error(`DELETE failed: ${c.value}`);
        u(`DELETE response: type=${c.type}, value=${c.value}`);
      }, async list(s) {
        var d, $, T;
        let i = await b(), l = (s == null ? void 0 : s.prefix) ?? "", c = (s == null ? void 0 : s.limit) ?? 10, h = m(l);
        u(`LIST: ${h}, limit: ${c}`);
        let p = ["list", h, "count", c.toString()];
        s != null && s.cursor && p.push("cursor", m(s.cursor));
        let g = await i.sendCommand(p);
        if (g.type === "array" && Array.isArray(g.value)) {
          let y = g.value;
          if (y.length >= 2) {
            let _ = { cursor: C(((d = y[0]) == null ? void 0 : d.value) || "") || void 0, complete: ((($ = y[1]) == null ? void 0 : $.value) || "").toLowerCase() === "true", keys: [] };
            for (let E = 2; E + 3 <= y.length; E += 3) {
              let G = { key: C(((T = y[E]) == null ? void 0 : T.value) || "") };
              _.keys.push(G);
            }
            return _;
          }
        }
        return { keys: [], complete: true };
      } };
    }
    function M() {
      let r = process.env[R];
      if (!r)
        return [];
      delete process.env[R];
      try {
        return JSON.parse(r);
      } catch {
        try {
          let e = Buffer.from(r, "base64").toString("utf-8");
          return JSON.parse(e);
        } catch {
          return [];
        }
      }
    }
    function z(r) {
      for (let e of r)
        globalThis[e.name] = S(e);
    }
    function re() {
      try {
        let r = M();
        r && r.length > 0 && (z(r), console.log(`[cli] Initialized ${r.length} KV binding(s)`));
      } catch {
        console.error("[cli] Initialization failed");
      }
    }
  })(kvModule, kvModule.exports);
  if (kvModule.exports.bootstrap) {
    await kvModule.exports.bootstrap();
  }
})();
var env = {
  "ProjectId": "makers-dirmmp2x67ci",
  "NG_CLI_ANALYTICS": "false",
  "NUXT_TELEMETRY_DISABLED": "1",
  "COREPACK_ENABLE_DOWNLOAD_PROMPT": "0",
  "COREPACK_ENABLE_STRICT": "0",
  "YARN_ENABLE_INTERACTIVE": "0",
  "NPM_CONFIG_YES": "true",
  "CI": "true",
  "TMPDIR": "C:\\Users\\Lukman\\AppData\\Local\\Temp",
  "UPLOAD_TOKEN": "0b0dbc8ac48b5d2256e579f7eb2714368693e7d0d05cc13e",
  "EDGEONE_PROJECT_ID": "makers-dirmmp2x67ci",
  "PAGES_PROJECT_ID": "makers-dirmmp2x67ci"
};
Object.assign(env, process.env || {});
delete env.TENCENTCLOUD_UIN;
delete env.TENCENTCLOUD_APPID;
function resolveAgentConversationId(_req) {
  return "";
}
function stripRequestSignal(request) {
  if (!request) {
    return request;
  }
  try {
    Object.defineProperty(request, "signal", {
      value: void 0,
      configurable: true
    });
  } catch {
  }
  return request;
}
function createCloudFunctionContext(options) {
  return {
    ...options.request ? { request: stripRequestSignal(options.request) } : {},
    env,
    params: options.params || {},
    uuid: options.req.headers["eo-log-uuid"] || "",
    server: {
      region: options.req.headers["x-scf-region"] || "",
      requestId: options.req.headers["x-scf-request-id"] || ""
    },
    clientIp: options.req.headers["eo-connecting-ip"] || "",
    geo: options.safeGeo
  };
}
function stripInternalRequestHeaders(req) {
  const rawRestricted = req.headers["x-cube-outer-flux-restricted"];
  const restrictedVal = Array.isArray(rawRestricted) ? rawRestricted[0] : rawRestricted;
  req.__edgeoneOuterFluxRestricted = typeof restrictedVal === "string" && restrictedVal.toLowerCase() === "true";
  for (const key in req.headers) {
    if (key.startsWith("x-scf-")) {
      delete req.headers[key];
    }
    if (key.startsWith("x-cube-")) {
      delete req.headers[key];
    }
  }
}
async function __edgeoneWithRestricted(req, fn) {
  const als = globalThis.__edgeoneRestrictedALS;
  if (!als)
    return fn();
  const store = {
    restricted: !!(req && req.__edgeoneOuterFluxRestricted),
    requestId: req && req.headers ? String(req.headers["x-scf-request-id"] || "") : ""
  };
  return als.run(store, fn);
}
function getResponsePassHeaders(context, _fallbackConversationId = "") {
  return {
    "functions-request-id": (context == null ? void 0 : context.server) ? context.server.requestId : ""
  };
}
try {
  process.removeAllListeners("uncaughtException");
  process.removeAllListeners("unhandledRejection");
  process.on("uncaughtException", (error) => {
    console.error("Uncaught Exception:", error);
  });
  process.on("unhandledRejection", (reason, promise) => {
    console.error("Unhandled Rejection:", reason);
  });
} catch (error) {
  console.error("Uncaught Exception:", error);
}
var port = 9e3;
var EdgeoneBodyParser = class {
  /**
   * Parse request body according to Content-Type, strictly following Edgeone rules
   * @param {Buffer} buffer Raw request body data
   * @param {string} contentType Content-Type header
   * @returns Parsed data
   */
  static parseBodyByContentType(buffer, contentType = "") {
    if (!buffer || buffer.length === 0) {
      return void 0;
    }
    const normalizedContentType = contentType.split(";")[0].trim().toLowerCase();
    switch (normalizedContentType) {
      case "application/json":
        try {
          const text = buffer.toString("utf-8");
          return JSON.parse(text);
        } catch (error) {
          throw new Error(`Invalid JSON in request body: ${error.message}`);
        }
      case "application/x-www-form-urlencoded":
        const formText = buffer.toString("utf-8");
        const params = new URLSearchParams(formText);
        const result = {};
        for (const [key, value] of params) {
          result[key] = value;
        }
        return result;
      case "text/plain":
        return buffer.toString("utf-8");
      case "application/octet-stream":
        return buffer;
      default:
        return buffer;
    }
  }
  /**
   * Parse URL query parameters
   * @param {string} url Full URL or query string
   * @returns {Object} Parsed query parameters object
   */
  static parseQuery(url) {
    if (!url)
      return {};
    const queryStart = url.indexOf("?");
    const queryString = queryStart >= 0 ? url.substring(queryStart + 1) : url;
    if (!queryString)
      return {};
    const params = {};
    const pairs = queryString.split("&");
    for (const pair of pairs) {
      if (!pair)
        continue;
      const equalIndex = pair.indexOf("=");
      let key, value;
      if (equalIndex === -1) {
        key = pair;
        value = true;
      } else if (equalIndex === 0) {
        continue;
      } else {
        key = pair.substring(0, equalIndex);
        value = pair.substring(equalIndex + 1);
        if (value === "") {
          value = "";
        }
      }
      if (key) {
        try {
          const decodedKey = decodeURIComponent(key);
          let decodedValue;
          if (typeof value === "boolean") {
            decodedValue = value;
          } else {
            decodedValue = decodeURIComponent(value);
            if (decodedValue === "true") {
              decodedValue = true;
            } else if (decodedValue === "false") {
              decodedValue = false;
            } else if (decodedValue === "null") {
              decodedValue = null;
            } else if (decodedValue === "undefined") {
              decodedValue = void 0;
            } else if (/^-?d+$/.test(decodedValue)) {
              const num = parseInt(decodedValue, 10);
              if (!isNaN(num) && num.toString() === decodedValue) {
                decodedValue = num;
              }
            } else if (/^-?d*.d+$/.test(decodedValue)) {
              const num = parseFloat(decodedValue);
              if (!isNaN(num) && num.toString() === decodedValue) {
                decodedValue = num;
              }
            }
          }
          if (params[decodedKey] !== void 0) {
            if (Array.isArray(params[decodedKey])) {
              params[decodedKey].push(decodedValue);
            } else {
              params[decodedKey] = [params[decodedKey], decodedValue];
            }
          } else {
            params[decodedKey] = decodedValue;
          }
        } catch (error) {
          if (typeof value === "boolean") {
            params[key] = value;
          } else {
            params[key] = value || "";
          }
        }
      }
    }
    return params;
  }
  /**
   * Parse Cookie header
   * @param {string} cookieHeader Cookie header string
   * @returns {Object} Parsed cookies object
   */
  static parseCookies(cookieHeader) {
    const cookies = {};
    if (!cookieHeader || typeof cookieHeader !== "string") {
      return cookies;
    }
    cookieHeader.split(";").forEach((cookie) => {
      const trimmed = cookie.trim();
      const equalIndex = trimmed.indexOf("=");
      if (equalIndex > 0) {
        const name = trimmed.substring(0, equalIndex).trim();
        let value = trimmed.substring(equalIndex + 1).trim();
        if (value.startsWith('"') && value.endsWith('"')) {
          value = value.slice(1, -1);
        }
        try {
          cookies[name] = decodeURIComponent(value);
        } catch (error) {
          cookies[name] = value;
        }
      }
    });
    return cookies;
  }
  /**
   * Read the full request body data from the stream
   */
  static async readBodyFromStream(req, maxSize = 50 * 1024 * 1024) {
    return new Promise((resolve, reject) => {
      if (req.readableEnded || req.destroyed) {
        resolve(Buffer.alloc(0));
        return;
      }
      if (req._bodyBuffer !== void 0) {
        resolve(req._bodyBuffer);
        return;
      }
      const chunks = [];
      let totalSize = 0;
      const cleanup = () => {
        req.removeListener("data", onData);
        req.removeListener("end", onEnd);
        req.removeListener("error", onError);
      };
      const onData = (chunk) => {
        totalSize += chunk.length;
        if (totalSize > maxSize) {
          cleanup();
          reject(new Error(`Request body too large. Max size: ${maxSize} bytes`));
          return;
        }
        chunks.push(chunk);
      };
      const onEnd = () => {
        cleanup();
        const buffer = Buffer.concat(chunks);
        req._bodyBuffer = buffer;
        resolve(buffer);
      };
      const onError = (error) => {
        cleanup();
        reject(error);
      };
      req.on("data", onData);
      req.on("end", onEnd);
      req.on("error", onError);
      if (req.readable && !req.readableFlowing) {
        req.resume();
      }
    });
  }
};
function firstForwardedProto(value) {
  const raw = Array.isArray(value) ? value[0] : value;
  return String(raw || "").split(",")[0].trim().toLowerCase();
}
function createBodyReadError(code, message, cause) {
  const err = new Error(message);
  err.code = code;
  if (cause)
    err.cause = cause;
  return err;
}
async function readIncomingBody(req) {
  const chunks = [];
  let size = 0;
  try {
    for await (const chunk of req) {
      size += chunk.length;
      chunks.push(chunk);
    }
  } catch (error) {
    throw createBodyReadError(
      "EO_BODY_READ_FAILED",
      "Request body read failed after " + size + " bytes: " + (error && error.message || String(error)),
      error
    );
  }
  const buf = chunks.length === 0 ? Buffer.alloc(0) : Buffer.concat(chunks, size);
  const declaredRaw = req.headers && req.headers["content-length"];
  if (declaredRaw !== void 0 && declaredRaw !== "") {
    const declared = Number(declaredRaw);
    if (Number.isFinite(declared) && declared !== buf.length) {
      throw createBodyReadError("EO_BODY_TRUNCATED", "Request body truncated: received " + buf.length + " of " + declared + " bytes");
    }
  }
  return buf;
}
function respondBodyReadError(req, res, error, pathname2) {
  const code = error && error.code || "EO_BODY_READ_FAILED";
  const status = 400;
  const requestId = req.headers["x-scf-request-id"] || req.headers["functions-request-id"] || "";
  try {
    console.error("[body-read] failed " + JSON.stringify({
      scfRequestId: requestId,
      method: req.method,
      path: pathname2,
      contentLength: req.headers["content-length"] || "",
      transferEncoding: req.headers["transfer-encoding"] || "",
      reqComplete: !!req.complete,
      reqAborted: !!req.aborted,
      reqDestroyed: !!req.destroyed,
      code,
      error: (error && error.name ? error.name + ": " : "") + (error && error.message || String(error)),
      cause: error && error.cause ? String(error.cause.message || error.cause) : ""
    }));
  } catch {
  }
  if (res.headersSent || res.writableEnded)
    return;
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Functions-Request-Id": requestId,
    "eo-pages-inner-body-error": code
  });
  res.end(JSON.stringify({
    error: "Request body read failed",
    code,
    message: error && error.message || "",
    functions_request_id: requestId || null
  }));
}
async function createEdgeoneCompatibleRequest(originalReq, isFramework = false) {
  const method = (originalReq.method || "GET").toUpperCase();
  const protocol = firstForwardedProto(originalReq.headers["x-forwarded-proto"]) || "http";
  const host = originalReq.headers.host || "localhost";
  const url = protocol + "://" + host + (originalReq.url || "/");
  const headerPairs = [];
  for (const key in originalReq.headers) {
    const v = originalReq.headers[key];
    if (typeof v === "string") {
      headerPairs.push([key, v]);
    } else if (Array.isArray(v)) {
      headerPairs.push([key, v.join(", ")]);
    } else if (v != null) {
      headerPairs.push([key, String(v)]);
    }
  }
  const init = {
    method,
    headers: new Headers(headerPairs)
  };
  let rawBody = void 0;
  let bodyReadError = null;
  if (method !== "GET" && method !== "HEAD") {
    try {
      rawBody = await readIncomingBody(originalReq);
    } catch (err) {
      bodyReadError = err;
    }
    if (rawBody && rawBody.length > 0) {
      init.body = rawBody;
    }
  }
  const request = new Request(url, init);
  request._rawBodyBuffer = rawBody;
  request._bodyReadError = bodyReadError;
  let parsedBodyCache = void 0;
  let parsedBodyReady = false;
  let parsedBodyError = null;
  const contentType = request.headers.get("content-type") || "";
  const ensureParsedBody = () => {
    if (parsedBodyReady)
      return;
    parsedBodyReady = true;
    if (bodyReadError) {
      parsedBodyError = bodyReadError;
      return;
    }
    try {
      parsedBodyCache = EdgeoneBodyParser.parseBodyByContentType(rawBody, contentType);
    } catch (err) {
      parsedBodyError = err;
    }
  };
  if (!("cookies" in request)) {
    Object.defineProperty(request, "cookies", {
      get() {
        return EdgeoneBodyParser.parseCookies(request.headers.get("cookie") || "");
      },
      configurable: true,
      enumerable: true
    });
  }
  if (!("query" in request)) {
    Object.defineProperty(request, "query", {
      get() {
        return EdgeoneBodyParser.parseQuery(request.url || "");
      },
      configurable: true,
      enumerable: true
    });
  }
  Object.defineProperty(request, "body", {
    get() {
      ensureParsedBody();
      if (parsedBodyError)
        throw parsedBodyError;
      return parsedBodyCache;
    },
    configurable: true,
    enumerable: true
  });
  return request;
}
async function handleResponse(res, response, passHeaders = {}) {
  var _a, _b, _c;
  const startTime = Date.now();
  const conversationId = passHeaders["makers-conversation-id"] || "";
  if (!response) {
    const requestId = passHeaders["functions-request-id"] || "";
    const headers = {
      "Functions-Request-Id": requestId,
      "eo-pages-inner-scf-status": "404",
      "eo-pages-inner-status-intercept": "true"
    };
    if (conversationId) {
      headers["makers-conversation-id"] = conversationId;
    }
    res.writeHead(404, headers);
    res.end(JSON.stringify({
      error: "Not Found",
      message: "The requested path does not exist"
    }));
    const endTime = Date.now();
    return;
  }
  try {
    if (response instanceof Response) {
      let validateCacheControlHeader = function(headers2) {
        const cacheControl = headers2["cache-control"];
        if (cacheControl) {
          const directives = cacheControl.split(",").map((directive) => directive.trim());
          const validatedDirectives = [];
          for (const directive of directives) {
            if (!directive)
              continue;
            const [key, value] = directive.split("=");
            const standardDirectives = ["max-age", "public", "private", "s-maxage", "no-cache", "no-store", "no-transform", "must-revalidate", "proxy-revalidate", "must-understand", "stale-while-revalidate", "stale-if-error", "immutable"];
            if (!standardDirectives.includes(key)) {
              continue;
            }
            if (key === "stale-while-revalidate" || key === "stale-if-error") {
              if (!value) {
                const defaultValue = "31536000";
                validatedDirectives.push(key + "=" + defaultValue);
                continue;
              }
            }
            validatedDirectives.push(directive);
          }
          headers2["cache-control"] = validatedDirectives.join(", ");
        }
      };
      const requestId = passHeaders["functions-request-id"] || "";
      const responseStatus = response.status;
      const headers = Object.fromEntries(response.headers);
      validateCacheControlHeader(headers);
      headers["Functions-Request-Id"] = requestId;
      if (conversationId) {
        headers["makers-conversation-id"] = conversationId;
      }
      if (!headers["eo-pages-inner-scf-status"]) {
        headers["eo-pages-inner-scf-status"] = String(responseStatus);
      }
      if (!headers["eo-pages-inner-status-intercept"]) {
        headers["eo-pages-inner-status-intercept"] = "false";
      }
      if (response.headers.get("eop-client-geo")) {
        response.headers.delete("eop-client-geo");
      }
      delete headers["x-content-type-stream"];
      delete headers["X-Content-Type-Stream"];
      const isStream = response.body && (((_a = response.headers.get("content-type")) == null ? void 0 : _a.includes("text/event-stream")) || ((_b = response.headers.get("transfer-encoding")) == null ? void 0 : _b.includes("chunked")) || response.body instanceof ReadableStream || typeof response.body.pipe === "function" || response.headers.get("x-content-type-stream") === "true");
      if (isStream) {
        const streamHeaders = {
          ...headers
        };
        if ((_c = response.headers.get("content-type")) == null ? void 0 : _c.includes("text/event-stream")) {
          streamHeaders["Content-Type"] = "text/event-stream";
        }
        res.writeHead(response.status, streamHeaders);
        if (typeof response.body.pipe === "function") {
          response.body.pipe(res);
        } else {
          const reader = response.body.getReader();
          try {
            while (true) {
              const { done, value } = await reader.read();
              if (done)
                break;
              if (value instanceof Uint8Array || Buffer.isBuffer(value)) {
                res.write(value);
              } else {
                const chunk = new TextDecoder().decode(value);
                res.write(chunk);
              }
            }
          } finally {
            reader.releaseLock();
            res.end();
          }
        }
      } else {
        res.writeHead(response.status, headers);
        const body = await response.text();
        res.end(body);
      }
    } else {
      const requestId = passHeaders["functions-request-id"] || "";
      const headers = {
        "Content-Type": "application/json",
        "Functions-Request-Id": requestId,
        "eo-pages-inner-scf-status": "200",
        "eo-pages-inner-status-intercept": "false"
      };
      if (conversationId) {
        headers["makers-conversation-id"] = conversationId;
      }
      res.writeHead(200, headers);
      res.end(JSON.stringify(response));
    }
  } catch (error) {
    const requestId = passHeaders["functions-request-id"] || "";
    const headers = {
      "Functions-Request-Id": requestId,
      "eo-pages-inner-scf-status": "502",
      "eo-pages-inner-status-intercept": "true"
    };
    if (conversationId) {
      headers["makers-conversation-id"] = conversationId;
    }
    res.writeHead(502, headers);
    res.end(JSON.stringify({
      error: "Internal Server Error",
      message: error.message
    }));
  } finally {
    const endTime = Date.now();
  }
}
var server = http.createServer(async (req, res) => {
  let agentConversationId = "";
  let fullPath = "";
  try {
    const requestStartTime = Date.now();
    const geoStr = decodeURIComponent(req.headers["eo-connecting-geo"]) || "";
    const geo = geoStr ? (() => {
      const result = {};
      const matches = geoStr.match(/[a-z_]+="[^"]*"|[a-z_]+=[A-Za-z0-9.-]+/g) || [];
      matches.forEach((match) => {
        const [key, value] = match.split("=", 2);
        result[key] = value.replace(/^"|"$/g, "");
      });
      return result;
    })() : {};
    const newGeo = {
      asn: geo.asn,
      countryName: geo.nation_name,
      countryCodeAlpha2: geo.region_code && geo.region_code.split("-")[0],
      countryCodeNumeric: geo.nation_numeric,
      regionName: geo.region_name,
      regionCode: geo.region_code,
      cityName: geo.city_name,
      latitude: geo.latitude,
      longitude: geo.longitude,
      cisp: geo.network_operator
    };
    const safeGeo = {};
    for (const [key, value] of Object.entries(newGeo)) {
      if (value !== void 0 && value !== null) {
        if (typeof value === "string" && /[\u4e00-\u9fff]/.test(value)) {
          safeGeo[key] = Buffer.from(value, "utf8").toString("utf8");
        } else {
          safeGeo[key] = value;
        }
      }
    }
    req.headers["eo-connecting-geo"] = safeGeo;
    let context = {};
    let enhancedRequest = {};
    req.headers["functions-request-id"] = req.headers["x-scf-request-id"] || "";
    agentConversationId = resolveAgentConversationId(req);
    const url = new URL(req.url, `http://${req.headers.host}`);
    let pathname2 = url.pathname;
    if (pathname2 !== "/" && pathname2.endsWith("/")) {
      pathname2 = pathname2.slice(0, -1);
    }
    if (req.headers.host === "localhost:9000") {
      fullPath = pathname2;
    } else {
      const host = req.headers["eo-pages-host"] || req.headers.host || "";
      const xForwardedProto = firstForwardedProto(req.headers["x-forwarded-proto"]);
      fullPath = (xForwardedProto || "https") + "://" + host + req.url;
      if (fullPath.endsWith("?")) {
        fullPath = fullPath.slice(0, -1);
      }
    }
    if (!req.headers["eo-pages-host"] || req.headers["eo-pages-host"] === "localhost:9000" || req.headers["eo-pages-host"] === "undefined" || req.headers["eo-pages-host"] === "null" || req.headers.host === "localhost:9000") {
      console.log(`Makers request info: ${JSON.stringify({
        host: req.headers.host,
        "user-agent": req.headers["user-agent"],
        "eo-pages-host": req.headers["eo-pages-host"],
        "eo-connecting-ip": req.headers["eo-connecting-ip"],
        "x-forwarded-for": req.headers["x-forwarded-for"],
        "x-real-ip": req.headers["x-real-ip"],
        "functions-request-id": req.headers["functions-request-id"],
        path: pathname2,
        url: req.url
      })}`);
    }
    const scfRequestId = req.headers["x-scf-request-id"] || "";
    let response = null;
    if (pathname2 === "/api/upload-url") {
      const mod_0 = (() => {
        var __create = Object.create;
        var __defProp = Object.defineProperty;
        var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
        var __getOwnPropNames = Object.getOwnPropertyNames;
        var __getProtoOf = Object.getPrototypeOf;
        var __hasOwnProp = Object.prototype.hasOwnProperty;
        var __commonJS = (cb, mod) => function __require2() {
          return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
        };
        var __copyProps = (to, from, except, desc) => {
          if (from && typeof from === "object" || typeof from === "function") {
            for (let key of __getOwnPropNames(from))
              if (!__hasOwnProp.call(to, key) && key !== except)
                __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
          }
          return to;
        };
        var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
          // If the importer is in node compatibility mode or this is not an ESM
          // file that has been converted to a CommonJS file using a Babel-
          // compatible transform (i.e. "__esModule" has not been set), then set
          // "default" to the CommonJS "module.exports" for node compatibility.
          isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
          mod
        ));
        var require_dist = __commonJS({
          "node_modules/@edgeone/pages-blob/dist/index.js"(exports, module) {
            "use strict";
            var U = Object.defineProperty;
            var ge = Object.getOwnPropertyDescriptor;
            var fe = Object.getOwnPropertyNames;
            var he = Object.prototype.hasOwnProperty;
            var me = (t, e) => {
              for (var n in e)
                U(t, n, { get: e[n], enumerable: true });
            };
            var ye = (t, e, n, r) => {
              if (e && typeof e == "object" || typeof e == "function")
                for (let s of fe(e))
                  !he.call(t, s) && s !== n && U(t, s, { get: () => e[s], enumerable: !(r = ge(e, s)) || r.enumerable });
              return t;
            };
            var pe = (t) => ye(U({}, "__esModule", { value: true }), t);
            var Le = {};
            me(Le, { InvalidKeyError: () => w, InvalidStoreNameError: () => p, MissingProjectIdError: () => S, PagesBlobError: () => m, PreconditionFailedError: () => b, QuotaExceededError: () => x, RateLimitedError: () => B, Store: () => T, getStore: () => _e, listStores: () => Ne });
            module.exports = pe(Le);
            var m = class extends Error {
              code;
              constructor(e, n) {
                super(`PagesBlob: ${n}`), this.name = "PagesBlobError", this.code = e;
              }
            };
            var w = class extends m {
              constructor(e) {
                super("INVALID_KEY", e);
              }
            };
            var p = class extends m {
              constructor(e) {
                super("INVALID_STORE_NAME", e);
              }
            };
            var E = class extends m {
              constructor(e) {
                super("MISSING_ENVIRONMENT", `Environment not configured for Pages Blob. Missing: ${e.join(", ")}. Supply these properties when creating a store, or ensure the function is running in a Pages environment.`);
              }
            };
            var we = "If usage just dropped back under the limit, wait a few minutes and retry.";
            var Ce = { storage: "write denied: storage quota exceeded (free plan 1 GB). Reads and deletes still work; delete objects or upgrade the plan.", "complex-operations": "write denied: complex operation quota (writes and lists) exceeded. Reads and deletes still work; upgrade the plan or wait until usage is back under the limit.", egress: "write denied: egress bandwidth quota exceeded. Only deletes still work; upgrade the plan or wait until usage is back under the limit." };
            var x = class extends m {
              reason;
              overMetrics;
              constructor(e = {}) {
                let n = e.reason && Ce[e.reason] || "write denied: blob quota exceeded.";
                super("QUOTA_EXCEEDED", `${n} ${we}`), this.reason = e.reason, this.overMetrics = e.overMetrics ?? [];
              }
            };
            var B = class extends m {
              constructor() {
                super("RATE_LIMITED", "request rate limited, please retry later");
              }
            };
            var S = class extends m {
              constructor() {
                super("MISSING_PROJECT_ID", "projectId is required when using API token mode. Please supply { name, projectId, token } to getStore() / listStores().");
              }
            };
            var y = class extends m {
              constructor(e) {
                super("CREDENTIAL_ERROR", e);
              }
            };
            var h = class extends m {
              statusCode;
              constructor(e, n) {
                super("COS_ERROR", `COS returned ${e}: ${n}`), this.statusCode = e;
              }
            };
            var b = class extends m {
              constructor() {
                super("PRECONDITION_FAILED", "conditional write failed (key already exists)");
              }
            };
            function C(t) {
              if (t === "")
                throw new w("Blob key must not be empty.");
              if (t.startsWith("/") || t.startsWith("%2F"))
                throw new w("Blob key must not start with forward slash (/).");
              if (new TextEncoder().encode(t).length > 600)
                throw new w("Blob key must be a sequence of Unicode characters whose UTF-8 encoding is at most 600 bytes long.");
            }
            function F(t) {
              if (t === "")
                throw new p("Store name must not be empty.");
              if (t.includes("/") || t.includes(":"))
                throw new p("Store name must not contain forward slashes (/) or colons (:).");
              if (!/^[a-zA-Z0-9_-]+$/.test(t))
                throw new p("Store name must only contain letters, digits, underscores, and hyphens.");
              if (new TextEncoder().encode(t).length > 64)
                throw new p("Store name must be a sequence of Unicode characters whose UTF-8 encoding is at most 64 bytes long.");
            }
            var T = class {
              cosClient;
              storeName;
              defaultConsistency;
              constructor(e, n, r = "eventual") {
                this.cosClient = e, this.storeName = n, this.defaultConsistency = r;
              }
              resolveConsistency(e) {
                return e ?? this.defaultConsistency;
              }
              async set(e, n, r) {
                C(e);
                let s = await this.cosClient.putObject(this.storeName, e, n, { onlyIfNew: r == null ? void 0 : r.onlyIfNew, cacheControl: r == null ? void 0 : r.cacheControl });
                if ((r == null ? void 0 : r.onlyIfNew) && s.statusCode === 412)
                  throw new b();
              }
              async setJSON(e, n, r) {
                C(e);
                let s = JSON.stringify(n), o = await this.cosClient.putObject(this.storeName, e, s, { onlyIfNew: r == null ? void 0 : r.onlyIfNew, contentType: "application/json", cacheControl: r == null ? void 0 : r.cacheControl });
                if ((r == null ? void 0 : r.onlyIfNew) && o.statusCode === 412)
                  throw new b();
              }
              async createUploadUrl(e, n) {
                C(e);
                let { url: r, expiresAt: s } = await this.cosClient.createPresignedPutUrl(this.storeName, e, { expireSeconds: n == null ? void 0 : n.expireSeconds, contentType: n == null ? void 0 : n.contentType });
                return { url: r, key: e, expiresAt: s };
              }
              async get(e, n) {
                C(e);
                let r = this.resolveConsistency(n == null ? void 0 : n.consistency), s = await this.cosClient.getObject(this.storeName, e, r);
                if (s === null)
                  return null;
                let { body: o } = s, c = (n == null ? void 0 : n.type) ?? "text", i = new TextDecoder("utf-8");
                switch (c) {
                  case "text":
                    return i.decode(o);
                  case "json":
                    return JSON.parse(i.decode(o));
                  case "arrayBuffer":
                    return o.buffer.slice(o.byteOffset, o.byteOffset + o.byteLength);
                  case "blob":
                    return new Blob([o]);
                  case "stream":
                    return new ReadableStream({ start(d) {
                      d.enqueue(o), d.close();
                    } });
                  default:
                    return i.decode(o);
                }
              }
              async getMetadata(e, n) {
                C(e);
                let r = this.resolveConsistency(n == null ? void 0 : n.consistency);
                return this.cosClient.headObject(this.storeName, e, r);
              }
              async getWithHeaders(e, n) {
                C(e);
                let r = this.resolveConsistency(n == null ? void 0 : n.consistency), s = await this.cosClient.getObject(this.storeName, e, r);
                return s ? { body: new TextDecoder("utf-8").decode(s.body), headers: s.headers || {} } : null;
              }
              async delete(e) {
                C(e), await this.cosClient.deleteObject(this.storeName, e);
              }
              async list(e) {
                let n = (e == null ? void 0 : e.paginate) !== false, r = e == null ? void 0 : e.limit, s = [], o = [], c = this.resolveConsistency(e == null ? void 0 : e.consistency), i = (e == null ? void 0 : e.cursor) || "", d = true, a;
                for (; d; ) {
                  let l = r !== void 0 ? r - s.length : 1e3, g = Math.min(l, 1e3);
                  if (g <= 0)
                    break;
                  let u = await this.cosClient.listObjects(this.storeName, { prefix: e == null ? void 0 : e.prefix, delimiter: (e == null ? void 0 : e.directories) ? "/" : void 0, marker: i || void 0, maxKeys: g, consistency: c });
                  for (let f of u.contents)
                    s.push({ key: f.key, etag: f.etag });
                  o.push(...u.commonPrefixes), r !== void 0 && s.length >= r ? (s.length = r, (u.isTruncated || u.contents.length === g) && (a = u.nextMarker), d = false) : u.isTruncated ? !n && r === void 0 ? (a = u.nextMarker, d = false) : i = u.nextMarker : d = false;
                }
                return { blobs: s, directories: o, ...a ? { cursor: a } : {} };
              }
            };
            var xe = new TextEncoder();
            function K(t) {
              let e = xe.encode(t), n = new ArrayBuffer(e.byteLength), r = new Uint8Array(n);
              return r.set(e), r;
            }
            function V(t) {
              let e = t instanceof Uint8Array ? t : new Uint8Array(t), n = "";
              for (let r = 0; r < e.length; r++)
                n += e[r].toString(16).padStart(2, "0");
              return n;
            }
            async function W(t, e) {
              let n = await crypto.subtle.importKey("raw", K(t), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]), r = await crypto.subtle.sign("HMAC", n, K(e));
              return V(r);
            }
            async function be(t) {
              let e = await crypto.subtle.digest("SHA-1", K(t));
              return V(e);
            }
            function j(t) {
              return encodeURIComponent(t).replace(/[!'()*]/g, (e) => "%" + e.charCodeAt(0).toString(16).toUpperCase());
            }
            function I(t) {
              try {
                return decodeURIComponent(t);
              } catch {
                return t;
              }
            }
            function Ee(t) {
              return t.split("/").map((e) => I(e)).join("/");
            }
            function k(t) {
              return Ee(I(t));
            }
            function J(t) {
              return t.split("/").map((e) => j(I(e))).join("/");
            }
            var Se = /* @__PURE__ */ new Set(["cache-control", "content-disposition", "content-encoding", "content-length", "content-md5", "content-type", "expect", "expires", "if-match", "if-modified-since", "if-none-match", "if-unmodified-since", "origin", "range", "transfer-encoding"]);
            function Te(t) {
              return t === "host" || t === "x-cos-security-token" ? false : !!(Se.has(t) || t.startsWith("x-cos-"));
            }
            function X(t) {
              if (!t)
                return [];
              let e = [];
              for (let [n, r] of Object.entries(t))
                r != null && e.push([n.toLowerCase(), String(r)]);
              return e.sort(([n], [r]) => n < r ? -1 : n > r ? 1 : 0), e;
            }
            function Y(t) {
              return t.map(([e, n]) => `${j(e)}=${j(n)}`).join("&");
            }
            function G(t) {
              return t.map(([e]) => j(e)).join(";");
            }
            async function Z(t) {
              let e = t.method.toLowerCase(), n = t.pathname.startsWith("/") ? t.pathname : `/${t.pathname}`, r = Math.floor(Date.now() / 1e3), s = r + (t.expireSeconds ?? 3600), o = `${r};${s}`, i = X(t.headers).filter(([L]) => Te(L)), d = G(i), a = Y(i), l = X(t.query), g = G(l), u = Y(l), f = `${e}
${n}
${u}
${a}
`, _ = `sha1
${o}
${await be(f)}
`, N = await W(t.secretKey, o), de = await W(N, _), le = ["q-sign-algorithm=sha1", `q-ak=${t.secretId}`, `q-sign-time=${o}`, `q-key-time=${o}`, `q-header-list=${d}`, `q-url-param-list=${g}`, `q-signature=${de}`].join("&"), H = {};
              for (let [L, ue] of i)
                H[L] = ue;
              return { authorization: le, signedHeaders: H };
            }
            async function Q(t) {
              let e = new URL(t.domain), n = I(t.key), r = `/${k(t.key)}`, s = `/${J(n)}`;
              e.pathname = s;
              let { authorization: o } = await Z({ method: t.method, pathname: r, query: t.query, headers: t.headers, secretId: t.credential.secretId, secretKey: t.credential.secretKey, expireSeconds: t.expireSeconds });
              if (t.query)
                for (let [c, i] of Object.entries(t.query))
                  i != null && e.searchParams.set(c, String(i));
              for (let c of o.split("&")) {
                let i = c.indexOf("=");
                if (i === -1)
                  continue;
                let d = c.slice(0, i), a = c.slice(i + 1);
                e.searchParams.set(d, a);
              }
              return t.credential.sessionToken && e.searchParams.set("x-cos-security-token", t.credential.sessionToken), e.toString();
            }
            async function P(t) {
              let e = new URL(t.domain), n = t.key ? I(t.key) : "", r = t.key ? `/${k(t.key)}` : "/", s = n ? `/${J(n)}` : "/";
              if (e.pathname = s, t.query)
                for (let [g, u] of Object.entries(t.query))
                  u != null && e.searchParams.set(g, String(u));
              let { authorization: o } = await Z({ method: t.method, pathname: r, query: t.query, headers: t.headers, secretId: t.credential.secretId, secretKey: t.credential.secretKey }), c = new Headers();
              if (t.headers)
                for (let [g, u] of Object.entries(t.headers))
                  u != null && c.set(g, String(u));
              c.set("Authorization", o), t.credential.sessionToken && c.set("x-cos-security-token", t.credential.sessionToken);
              let i = e.toString(), d = { method: t.method, headers: c, body: t.body ?? void 0, signal: t.signal }, a = 2, l;
              for (let g = 0; g <= a; g++)
                try {
                  return await fetch(i, d);
                } catch (u) {
                  if (l = u, u instanceof DOMException && u.name === "AbortError")
                    throw u;
                  g < a && await new Promise((f) => setTimeout(f, 1e3 * (g + 1)));
                }
              throw l;
            }
            var Pe = "blob.edgeone.site";
            var Ie = "blob-nocache.edgeone.site";
            var ke = "max-age=0, stale-while-revalidate=60";
            var D = class t {
              credentialManager;
              bucket = "";
              region = "";
              keyPrefix = "";
              cachedDomain = "";
              uncachedDomain = "";
              initialized = false;
              static buildErrorDetail(e, n, r, s, o) {
                let c = r ? `${n}/${r}` : n, i = o ? ` [request-id: ${o}]` : "";
                return `${e} ${c} - ${Ae(s)}${i}`;
              }
              constructor(e) {
                this.credentialManager = e;
              }
              computeSubdomain(e) {
                let n = [];
                if (e.appId && n.push(e.appId), e.zoneId && n.push(e.zoneId), e.projectId && n.push(e.projectId), n.length >= 2)
                  return n.join("-");
                if (e.resourcePrefix) {
                  let s = e.resourcePrefix.replace(/\/?\*$/, "").split("/").filter(Boolean);
                  if (s.length >= 2)
                    return s.slice(0, Math.min(s.length, 3)).join("-");
                }
                return "";
              }
              async ensureInitialized() {
                if (this.initialized)
                  return;
                let e = await this.credentialManager.getCredential();
                !this.keyPrefix && e.resourcePrefix && (this.keyPrefix = e.resourcePrefix.replace(/\/?\*$/, ""));
                let n = e.edgeRegion === "CN", r = e.cosMainland, s = e.cosOverseas, o = n ? r || s : s || r;
                !this.bucket && o && (this.bucket = o.bucket, this.region = o.region);
                let { cachedDomain: c, uncachedDomain: i } = e;
                if (!c || !i) {
                  let d = this.computeSubdomain(e);
                  if (!d)
                    throw new h(0, "unable to derive tenant subdomain from credential; missing appId/zoneId/projectId or resourcePrefix");
                  c || (c = `https://${d}.${Pe}`), i || (i = `https://${d}.${Ie}`);
                }
                this.cachedDomain = c, this.uncachedDomain = i, this.initialized = true;
              }
              async resolveDomain(e) {
                return await this.ensureInitialized(), e === "strong" ? this.uncachedDomain : this.cachedDomain;
              }
              async resolveCredential() {
                let e = await this.credentialManager.getCredential();
                return { secretId: e.tmpSecretId, secretKey: e.tmpSecretKey, sessionToken: e.sessionToken };
              }
              buildCosKey(e, n) {
                return `${this.keyPrefix}/${e}/${n}`;
              }
              async getDomains() {
                return await this.ensureInitialized(), { cached: this.cachedDomain, uncached: this.uncachedDomain };
              }
              async putObject(e, n, r, s) {
                let o = await this.resolveDomain("strong"), c = await this.ensureWriteAllowed(), i = await this.resolveCredential(), d = this.buildCosKey(e, n), { defaultCacheControl: a = ke } = c, l = (s == null ? void 0 : s.cacheControl) === null ? void 0 : (s == null ? void 0 : s.cacheControl) ?? a, g = {};
                (s == null ? void 0 : s.onlyIfNew) && (g["x-cos-forbid-overwrite"] = "true"), l && (g["Cache-Control"] = l), (s == null ? void 0 : s.contentType) && (g["Content-Type"] = s.contentType);
                let u;
                try {
                  let f = await P({ domain: o, method: "PUT", key: d, headers: g, body: r, credential: i });
                  if ((s == null ? void 0 : s.onlyIfNew) && (f.status === 409 || f.status === 412))
                    return await f.arrayBuffer().catch(() => {
                    }), { etag: "", statusCode: 412 };
                  if (f.ok) {
                    let N = f.headers.get("etag") || "";
                    return await f.arrayBuffer().catch(() => {
                    }), { etag: N, statusCode: f.status };
                  }
                  let _ = await A(f);
                  u = new h(f.status, t.buildErrorDetail("PUT", o, d, _ || `status ${f.status}`, R(f)));
                } catch (f) {
                  u = new h(0, t.buildErrorDetail("PUT", o, d, v(f)));
                }
                throw await this.explainWriteFailure(u);
              }
              async ensureWriteAllowed() {
                let e = await this.credentialManager.getCredential();
                if (e.writeAllowed !== false)
                  return e;
                let n = e;
                try {
                  n = await this.credentialManager.refreshCredential();
                } catch {
                }
                return ee(n), n;
              }
              async explainWriteFailure(e) {
                if (![0, 403, 550].includes(e.statusCode))
                  return e;
                try {
                  let n = await this.credentialManager.refreshCredential();
                  ee(n);
                } catch (n) {
                  if (n instanceof x)
                    return n;
                }
                return e;
              }
              async createPresignedPutUrl(e, n, r) {
                let s = await this.resolveDomain("strong");
                await this.ensureWriteAllowed();
                let o = await this.resolveCredential(), c = this.buildCosKey(e, n), i = {};
                (r == null ? void 0 : r.contentType) && (i["Content-Type"] = r.contentType);
                let d = (r == null ? void 0 : r.expireSeconds) ?? 3600, a = await Q({ domain: s, method: "PUT", key: c, headers: i, credential: o, expireSeconds: d }), l = Math.floor(Date.now() / 1e3) + d;
                return { url: a, expiresAt: l };
              }
              async getObject(e, n, r) {
                let s = await this.resolveDomain(r), o = await this.resolveCredential(), c = this.buildCosKey(e, n);
                try {
                  let i = await P({ domain: s, method: "GET", key: c, credential: o });
                  if (i.status === 404)
                    return await i.arrayBuffer().catch(() => {
                    }), null;
                  if (!i.ok) {
                    let l = await A(i);
                    throw new h(i.status, t.buildErrorDetail("GET", s, c, l || `status ${i.status}`, R(i)));
                  }
                  let d = new Uint8Array(await i.arrayBuffer()), a = te(i.headers);
                  return { body: d, contentType: a["content-type"], headers: a };
                } catch (i) {
                  throw i instanceof h ? i : new h(0, t.buildErrorDetail("GET", s, c, v(i)));
                }
              }
              async headObject(e, n, r) {
                let s = await this.resolveDomain(r), o = await this.resolveCredential(), c = this.buildCosKey(e, n);
                try {
                  let i = await P({ domain: s, method: "HEAD", key: c, credential: o });
                  if (i.status === 404)
                    return null;
                  if (!i.ok) {
                    let a = await A(i);
                    throw new h(i.status, t.buildErrorDetail("HEAD", s, c, a || `status ${i.status}`, R(i)));
                  }
                  let d = te(i.headers);
                  return { cacheControl: d["cache-control"], contentType: d["content-type"], etag: d.etag, headers: d };
                } catch (i) {
                  throw i instanceof h ? i : new h(0, t.buildErrorDetail("HEAD", s, c, v(i)));
                }
              }
              async deleteObject(e, n) {
                let r = await this.resolveDomain("strong"), s = await this.resolveCredential(), o = this.buildCosKey(e, n);
                try {
                  let c = await P({ domain: r, method: "DELETE", key: o, credential: s });
                  if (c.status === 204 || c.status === 404 || c.ok) {
                    await c.arrayBuffer().catch(() => {
                    });
                    return;
                  }
                  let i = await A(c);
                  throw new h(c.status, t.buildErrorDetail("DELETE", r, o, i || `status ${c.status}`, R(c)));
                } catch (c) {
                  throw c instanceof h ? c : new h(0, t.buildErrorDetail("DELETE", r, o, v(c)));
                }
              }
              async listObjects(e, n) {
                await this.ensureInitialized();
                let r = `${this.keyPrefix}/${e}/`, s = (n == null ? void 0 : n.prefix) ? r + n.prefix : r, o = await this.getBucketRaw({ prefix: s, delimiter: n == null ? void 0 : n.delimiter, marker: n == null ? void 0 : n.marker, maxKeys: n == null ? void 0 : n.maxKeys, consistency: n == null ? void 0 : n.consistency }), c = o.contents.map((d) => {
                  let a = d.key, l = a.startsWith(r) ? a.slice(r.length) : a;
                  return l ? { key: l, etag: d.etag } : null;
                }).filter((d) => d !== null), i = o.commonPrefixes.map((d) => d.startsWith(r) ? d.slice(r.length) : d).filter((d) => !!d);
                return { contents: c, commonPrefixes: i, isTruncated: o.isTruncated, nextMarker: o.nextMarker };
              }
              async listStores(e) {
                let n = [], r = "", s = true;
                for (; s; ) {
                  await this.ensureInitialized();
                  let o = `${this.keyPrefix}/`, c = await this.getBucketRaw({ prefix: o, delimiter: "/", maxKeys: 1e3, marker: r || void 0, consistency: e });
                  for (let i of c.commonPrefixes) {
                    let d = i.startsWith(o) ? i.slice(o.length, -1) : i.slice(0, -1);
                    d && n.push(d);
                  }
                  if (s = c.isTruncated, r = c.nextMarker, !s || !r)
                    break;
                }
                return n;
              }
              async getBucketRaw(e) {
                let n = await this.resolveDomain(e.consistency), r = await this.resolveCredential(), s = { prefix: k(e.prefix) };
                e.delimiter && (s.delimiter = e.delimiter), e.marker && (s.marker = k(e.marker)), e.maxKeys && (s["max-keys"] = e.maxKeys);
                try {
                  let o = await P({ domain: n, method: "GET", query: s, credential: r });
                  if (!o.ok) {
                    let i = await A(o);
                    throw new h(o.status, t.buildErrorDetail("LIST", n, e.prefix, i || `status ${o.status}`, R(o)));
                  }
                  let c = await o.text();
                  return Re(c);
                } catch (o) {
                  throw o instanceof h ? o : new h(0, t.buildErrorDetail("LIST", n, e.prefix, v(o)));
                }
              }
            };
            function ee(t) {
              if (t.writeAllowed === false)
                throw new x({ reason: t.writeDeniedReason, overMetrics: t.overMetrics });
            }
            function Ae(t) {
              return t.replace(/[a-zA-Z0-9\-]+\.cos\.[a-zA-Z0-9\-.]+\.myqcloud\.com/gi, "[cos-origin]").replace(/[a-zA-Z0-9\-]+\.cos\.[a-zA-Z0-9\-.]+\.tencentcos\.cn/gi, "[cos-origin]");
            }
            async function A(t) {
              try {
                return await t.text();
              } catch {
                return "";
              }
            }
            function R(t) {
              return t.headers.get("x-cos-request-id") || t.headers.get("x-eo-log-id") || void 0;
            }
            function v(t) {
              let e = t, n = e.message || String(t), r = e.cause;
              if (r) {
                let s = r.message || r.code || "";
                return s ? `${n} (${s})` : n;
              }
              return n;
            }
            function te(t) {
              let e = {};
              return t.forEach((n, r) => {
                e[r.toLowerCase()] = n;
              }), e;
            }
            function Re(t) {
              let e = [], n = /<Contents>([\s\S]*?)<\/Contents>/g, r;
              for (; (r = n.exec(t)) !== null; ) {
                let a = r[1], l = M(a, "Key"), g = M(a, "ETag");
                l !== null && e.push({ key: q(l), etag: g || "" });
              }
              let s = [], o = /<CommonPrefixes>([\s\S]*?)<\/CommonPrefixes>/g;
              for (; (r = o.exec(t)) !== null; ) {
                let a = r[1], l = M(a, "Prefix");
                l !== null && s.push(q(l));
              }
              let i = M(t, "IsTruncated") === "true", d = M(t, "NextMarker") || "";
              return { contents: e, commonPrefixes: s, isTruncated: i, nextMarker: q(d) };
            }
            function M(t, e) {
              let r = new RegExp(`<${e}>([\\s\\S]*?)<\\/${e}>`).exec(t);
              return r ? r[1] : null;
            }
            function q(t) {
              return t.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&");
            }
            var ve = "X-RateLimit-Reset";
            async function $(t, e, n = 2) {
              var _a, _b;
              (_b = (_a = e.signal) == null ? void 0 : _a.throwIfAborted) == null ? void 0 : _b.call(_a);
              try {
                let r = await fetch(t, e);
                if (n > 0 && (r.status === 429 || r.status >= 500)) {
                  let s = ne(r.headers.get(ve));
                  return await re(s, e.signal), $(t, e, n - 1);
                }
                return r;
              } catch (r) {
                if (n === 0 || r instanceof DOMException && r.name === "AbortError")
                  throw r;
                let s = ne();
                return await re(s, e.signal), $(t, e, n - 1);
              }
            }
            function ne(t) {
              return t ? Math.max(Number(t) * 1e3 - Date.now(), 500) : 1500;
            }
            function re(t, e) {
              return new Promise((n, r) => {
                if (e == null ? void 0 : e.aborted)
                  return r(e.reason);
                let s = setTimeout(() => {
                  e == null ? void 0 : e.removeEventListener("abort", o), n();
                }, t), o = () => {
                  clearTimeout(s), r(e.reason);
                };
                e == null ? void 0 : e.addEventListener("abort", o, { once: true });
              });
            }
            var Me = "prod";
            function se() {
              let t = typeof process < "u" ? process.env.PAGES_BLOB_STS_ENV : void 0;
              return t === "test" || t === "prod" ? t : Me;
            }
            var De = 300;
            var Oe = 6e4;
            var Be = "https://blob-sts.edgeone.site/";
            var O = class {
              authToken;
              projectId;
              cached = null;
              lastForcedRefreshAt = 0;
              constructor(e, n) {
                this.authToken = e, this.projectId = n;
              }
              async getCredential() {
                if (this.cached && !this.isExpired(this.cached))
                  return this.cached;
                let e = await this.fetchCredential();
                return this.cached = e, e;
              }
              async refreshCredential() {
                if (this.cached && Date.now() - this.lastForcedRefreshAt < Oe)
                  return this.cached;
                this.lastForcedRefreshAt = Date.now();
                let e = await this.fetchCredential(true);
                return this.cached = e, e;
              }
              clearCache() {
                this.cached = null;
              }
              isExpired(e) {
                let n = Math.floor(Date.now() / 1e3);
                return e.expiredTime - n < De;
              }
              async fetchCredential(e = false) {
                for (let s = 1; s <= 3; s++) {
                  let o = new AbortController(), c = setTimeout(() => o.abort(), 1e4), i;
                  try {
                    i = await $(Be, { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${this.authToken}`, "X-Env": se(), ...e ? { "X-SKIP-CACHE": "true" } : {} }, body: JSON.stringify(this.projectId ? { ProjectId: this.projectId } : {}), signal: o.signal });
                  } catch (l) {
                    if (s < 3) {
                      await z(500 * s);
                      continue;
                    }
                    throw new y(`failed to obtain STS credential: ${l.message || "timeout"}`);
                  } finally {
                    clearTimeout(c);
                  }
                  if (i.status === 413)
                    throw new y("storage quota exceeded");
                  if (i.status === 429)
                    throw new y("rate limited, please retry later");
                  if (!i.ok) {
                    if (i.status >= 500 && s < 3) {
                      await z(500 * s);
                      continue;
                    }
                    let l = await i.text().catch(() => "unknown error");
                    throw new y(`failed to obtain STS credential: ${i.status} ${l}`);
                  }
                  let d = await i.json(), a = d.data && typeof d.data == "object" ? d.data : d;
                  if (a.tmpSecretId && a.tmpSecretKey && a.sessionToken && a.expiredTime) {
                    let l = a.cosMainland, g = a.cosOverseas, u = i.headers.get("X-Edge-Region") || void 0;
                    return { tmpSecretId: a.tmpSecretId, tmpSecretKey: a.tmpSecretKey, sessionToken: a.sessionToken, expiredTime: a.expiredTime, appId: a.appId || void 0, zoneId: a.zoneId || void 0, projectId: a.projectId || void 0, resourcePrefix: a.resourcePrefix || void 0, cosMainland: l || void 0, cosOverseas: g || void 0, edgeRegion: u, defaultCacheControl: typeof a.defaultCacheControl == "string" && a.defaultCacheControl ? a.defaultCacheControl : void 0, cachedDomain: ie(a.cachedDomain), uncachedDomain: ie(a.uncachedDomain), writeAllowed: typeof a.writeAllowed == "boolean" ? a.writeAllowed : void 0, writeDeniedReason: typeof a.writeDeniedReason == "string" && a.writeDeniedReason ? a.writeDeniedReason : void 0, overMetrics: Array.isArray(a.overMetrics) ? a.overMetrics.filter((f) => typeof f == "string") : void 0 };
                  }
                  if (a.code !== void 0 && a.code !== 0) {
                    let l = a.msg || a.message || "unknown error";
                    throw new y(`credential exchange failed (code=${a.code}): ${l}`);
                  }
                  if (d.code !== void 0 && d.code !== 0) {
                    let l = d.msg || d.message || "unknown error";
                    throw new y(`credential exchange failed (code=${d.code}): ${l}`);
                  }
                  if (s < 3) {
                    await z(500 * s);
                    continue;
                  }
                  throw new y("invalid STS credential response");
                }
                throw new y("invalid STS credential response");
              }
            };
            function ie(t) {
              if (typeof t != "string")
                return;
              let e = t.trim().replace(/\/+$/, "");
              if (e)
                return /^https?:\/\//i.test(e) ? e : `https://${e}`;
            }
            function z(t) {
              return new Promise((e) => setTimeout(e, t));
            }
            var je = "{{PAGES_BLOB_DEPLOY_CREDENTIAL}}";
            function ae() {
              let t = {}, e = $e();
              if (e)
                t.deployCredential = e;
              else {
                let r = oe("PAGES_BLOB_DEPLOY_CREDENTIAL");
                r && (t.deployCredential = r);
              }
              let n = oe("PAGES_PROJECT_ID");
              return n && (t.projectId = n), t;
            }
            function $e() {
              let t = je;
              if (!(t.startsWith("{{") && t.endsWith("}}")))
                return t || void 0;
            }
            function oe(t) {
              if (typeof process < "u" && process.env)
                return process.env[t];
            }
            function _e(t) {
              let e = typeof t == "string" ? t : t.name;
              F(e);
              let n = ce(typeof t == "string" ? void 0 : t), r = new O(n.authToken, n.projectId), s = new D(r);
              return new T(s, e, n.consistency ?? "eventual");
            }
            async function Ne(t) {
              let e = ce(t ? { name: "__list__", projectId: t.projectId, token: t.token, consistency: t.consistency } : void 0), n = new O(e.authToken, e.projectId);
              return { stores: (await new D(n).listStores(e.consistency)).map((o) => ({ name: o })) };
            }
            function ce(t) {
              let e = ae(), n = (t == null ? void 0 : t.token) || e.deployCredential, r = (t == null ? void 0 : t.projectId) || e.projectId;
              if ((t == null ? void 0 : t.token) || e.projectId) {
                if (!r)
                  throw new S();
                if (!n)
                  throw new E(["token"]);
                return { authToken: n, projectId: r, consistency: t == null ? void 0 : t.consistency };
              }
              if ((t == null ? void 0 : t.projectId) && !n)
                throw new E(["token"]);
              if (!e.deployCredential)
                throw new E(["deployCredential"]);
              return { authToken: e.deployCredential, consistency: t == null ? void 0 : t.consistency };
            }
          }
        });
        var import_pages_blob = __toESM(require_dist());
        async function onRequest(context2) {
          const {
            request
          } = context2;
          if (request.method !== "POST")
            return new Response("Method Not Allowed", {
              status: 405
            });
          const token = context2.env && context2.env.UPLOAD_TOKEN || typeof process !== "undefined" && process.env && process.env.UPLOAD_TOKEN || "";
          if (!token)
            return new Response("UPLOAD_TOKEN belum terbaca di server (cek Environment Variables lalu redeploy)", {
              status: 500
            });
          if (request.headers.get("authorization") !== `Bearer ${token}`) {
            return new Response("Token tidak cocok", {
              status: 401
            });
          }
          const {
            name,
            contentType
          } = await request.json();
          if (!/^[a-z0-9._-]+\.(jpg|jpeg|png|webp)$/i.test(name || "")) {
            return new Response("Nama file tidak valid", {
              status: 400
            });
          }
          const out = await (0, import_pages_blob.getStore)("batik").createUploadUrl("img/" + name, {
            expireSeconds: 600,
            contentType: contentType || "application/octet-stream"
          });
          return new Response(JSON.stringify(out), {
            headers: {
              "Content-Type": "application/json"
            }
          });
        }
        return {
          onRequest: typeof onRequest !== "undefined" ? onRequest : void 0,
          onRequestGet: typeof onRequestGet !== "undefined" ? onRequestGet : void 0,
          onRequestPost: typeof onRequestPost !== "undefined" ? onRequestPost : void 0,
          onRequestPut: typeof onRequestPut !== "undefined" ? onRequestPut : void 0,
          onRequestDelete: typeof onRequestDelete !== "undefined" ? onRequestDelete : void 0,
          onRequestPatch: typeof onRequestPatch !== "undefined" ? onRequestPatch : void 0,
          onRequestHead: typeof onRequestHead !== "undefined" ? onRequestHead : void 0,
          onRequestOptions: typeof onRequestOptions !== "undefined" ? onRequestOptions : void 0
        };
      })();
      enhancedRequest = await createEdgeoneCompatibleRequest(req, false);
      if (enhancedRequest._bodyReadError) {
        respondBodyReadError(req, res, enhancedRequest._bodyReadError, pathname2);
        console.log("Makers request path: " + fullPath + " |scfRequestId=" + (req.headers["x-scf-request-id"] || "") + "|statusCode=400|");
        return;
      }
      context = createCloudFunctionContext({
        req,
        safeGeo,
        request: enhancedRequest,
        params: {},
        conversation_id: agentConversationId
      });
      stripInternalRequestHeaders(req);
      try {
        const handler = (() => {
          const method = req.method;
          if (method === "GET" && mod_0.onRequestGet) {
            return mod_0.onRequestGet;
          } else if (method === "POST" && mod_0.onRequestPost) {
            return mod_0.onRequestPost;
          } else if (method === "PUT" && mod_0.onRequestPut) {
            return mod_0.onRequestPut;
          } else if (method === "DELETE" && mod_0.onRequestDelete) {
            return mod_0.onRequestDelete;
          } else if (method === "PATCH" && mod_0.onRequestPatch) {
            return mod_0.onRequestPatch;
          } else if (method === "HEAD" && mod_0.onRequestHead) {
            return mod_0.onRequestHead;
          } else if (method === "OPTIONS" && mod_0.onRequestOptions) {
            return mod_0.onRequestOptions;
          } else {
            return mod_0.onRequest;
          }
        })();
        if (handler) {
          response = await __edgeoneWithRestricted(req, () => handler(context));
          if (response && typeof response === "object" && response.websocket) {
            console.log("[WebSocket] WebSocket configuration detected for:", pathname2);
            const upgradeHeader = req.headers["upgrade"];
            if (upgradeHeader && upgradeHeader.toLowerCase() === "websocket") {
              console.log("[WebSocket] Executing WebSocket handshake...");
              try {
                const { WebSocketServer } = __require("ws");
                const wss = new WebSocketServer({ noServer: true });
                wss.on("connection", (ws, request) => {
                  console.log("[WebSocket] Connection established");
                  if (response.websocket.onopen) {
                    try {
                      response.websocket.onopen(ws, request);
                    } catch (error) {
                      console.error("[WebSocket] Error in onopen:", error);
                    }
                  }
                  ws.on("message", (data, isBinary) => {
                    if (response.websocket.onmessage) {
                      try {
                        response.websocket.onmessage(ws, data, isBinary);
                      } catch (error) {
                        console.error("[WebSocket] Error in onmessage:", error);
                        ws.close(1011, "Internal error");
                      }
                    }
                  });
                  ws.on("close", (code, reason) => {
                    if (response.websocket.onclose) {
                      try {
                        response.websocket.onclose(ws, code, reason);
                      } catch (error) {
                        console.error("[WebSocket] Error in onclose:", error);
                      }
                    }
                  });
                  ws.on("error", (error) => {
                    if (response.websocket.onerror) {
                      try {
                        response.websocket.onerror(ws, error);
                      } catch (err) {
                        console.error("[WebSocket] Error in onerror:", err);
                      }
                    } else {
                      console.error("[WebSocket] Connection error:", error);
                    }
                  });
                });
                wss.handleUpgrade(req, req.socket, Buffer.alloc(0), (ws) => {
                  wss.emit("connection", ws, req);
                });
                console.log("[WebSocket] Handshake complete, connection established");
                return;
              } catch (wsError) {
                console.error("[WebSocket] Handshake error:", wsError);
                response = new Response(JSON.stringify({
                  error: "WebSocket Handshake Failed",
                  message: wsError.message
                }), {
                  status: 500,
                  headers: {
                    "Content-Type": "application/json"
                  }
                });
              }
            } else {
              response = new Response("WebSocket endpoint. Use ws:// protocol to connect.", {
                status: 426,
                headers: {
                  "Content-Type": "text/plain",
                  "Upgrade": "websocket"
                }
              });
            }
          }
        }
      } catch (handlerError) {
        console.log("Makers request path: " + fullPath + " |scfRequestId=" + (context.server ? context.server.requestId : "") + "|statusCode=502|");
        response = new Response(JSON.stringify({
          error: "Internal Server Error",
          message: handlerError.message
        }), {
          status: 502,
          headers: {
            "Content-Type": "application/json",
            // 'Functions-Request-Id': context.server ? context.server.requestId : '',
            "eo-pages-inner-scf-status": "502",
            "eo-pages-inner-status-intercept": "true"
          }
        });
      }
      const requestEndTime2 = Date.now();
      console.log("Makers request path: " + fullPath + " |scfRequestId=" + (context.server ? context.server.requestId : "") + "|statusCode=" + String((response == null ? void 0 : response.status) || 200) + "|");
      await handleResponse(res, response, getResponsePassHeaders(context, agentConversationId));
      return;
    }
    if (pathname2.startsWith("/img/")) {
      enhancedRequest = await createEdgeoneCompatibleRequest(req, false);
      if (enhancedRequest._bodyReadError) {
        respondBodyReadError(req, res, enhancedRequest._bodyReadError, pathname2);
        console.log("Makers request path: " + fullPath + " |scfRequestId=" + (req.headers["x-scf-request-id"] || "") + "|statusCode=400|");
        return;
      }
      context = createCloudFunctionContext({
        req,
        safeGeo,
        request: enhancedRequest,
        params: {},
        conversation_id: agentConversationId
      });
      stripInternalRequestHeaders(req);
      const routeMatch = pathname2.slice("/img/".length);
      const cleanPath = routeMatch.startsWith("/") ? routeMatch.slice(1) : routeMatch;
      if (cleanPath) {
        const params = {};
        params["path"] = cleanPath.split("/");
        context.params = params;
        const mod_1 = (() => {
          var __create = Object.create;
          var __defProp = Object.defineProperty;
          var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
          var __getOwnPropNames = Object.getOwnPropertyNames;
          var __getProtoOf = Object.getPrototypeOf;
          var __hasOwnProp = Object.prototype.hasOwnProperty;
          var __commonJS = (cb, mod) => function __require2() {
            return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
          };
          var __copyProps = (to, from, except, desc) => {
            if (from && typeof from === "object" || typeof from === "function") {
              for (let key of __getOwnPropNames(from))
                if (!__hasOwnProp.call(to, key) && key !== except)
                  __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
            }
            return to;
          };
          var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
            // If the importer is in node compatibility mode or this is not an ESM
            // file that has been converted to a CommonJS file using a Babel-
            // compatible transform (i.e. "__esModule" has not been set), then set
            // "default" to the CommonJS "module.exports" for node compatibility.
            isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
            mod
          ));
          var require_dist = __commonJS({
            "node_modules/@edgeone/pages-blob/dist/index.js"(exports, module) {
              "use strict";
              var U = Object.defineProperty;
              var ge = Object.getOwnPropertyDescriptor;
              var fe = Object.getOwnPropertyNames;
              var he = Object.prototype.hasOwnProperty;
              var me = (t, e) => {
                for (var n in e)
                  U(t, n, { get: e[n], enumerable: true });
              };
              var ye = (t, e, n, r) => {
                if (e && typeof e == "object" || typeof e == "function")
                  for (let s of fe(e))
                    !he.call(t, s) && s !== n && U(t, s, { get: () => e[s], enumerable: !(r = ge(e, s)) || r.enumerable });
                return t;
              };
              var pe = (t) => ye(U({}, "__esModule", { value: true }), t);
              var Le = {};
              me(Le, { InvalidKeyError: () => w, InvalidStoreNameError: () => p, MissingProjectIdError: () => S, PagesBlobError: () => m, PreconditionFailedError: () => b, QuotaExceededError: () => x, RateLimitedError: () => B, Store: () => T, getStore: () => _e, listStores: () => Ne });
              module.exports = pe(Le);
              var m = class extends Error {
                code;
                constructor(e, n) {
                  super(`PagesBlob: ${n}`), this.name = "PagesBlobError", this.code = e;
                }
              };
              var w = class extends m {
                constructor(e) {
                  super("INVALID_KEY", e);
                }
              };
              var p = class extends m {
                constructor(e) {
                  super("INVALID_STORE_NAME", e);
                }
              };
              var E = class extends m {
                constructor(e) {
                  super("MISSING_ENVIRONMENT", `Environment not configured for Pages Blob. Missing: ${e.join(", ")}. Supply these properties when creating a store, or ensure the function is running in a Pages environment.`);
                }
              };
              var we = "If usage just dropped back under the limit, wait a few minutes and retry.";
              var Ce = { storage: "write denied: storage quota exceeded (free plan 1 GB). Reads and deletes still work; delete objects or upgrade the plan.", "complex-operations": "write denied: complex operation quota (writes and lists) exceeded. Reads and deletes still work; upgrade the plan or wait until usage is back under the limit.", egress: "write denied: egress bandwidth quota exceeded. Only deletes still work; upgrade the plan or wait until usage is back under the limit." };
              var x = class extends m {
                reason;
                overMetrics;
                constructor(e = {}) {
                  let n = e.reason && Ce[e.reason] || "write denied: blob quota exceeded.";
                  super("QUOTA_EXCEEDED", `${n} ${we}`), this.reason = e.reason, this.overMetrics = e.overMetrics ?? [];
                }
              };
              var B = class extends m {
                constructor() {
                  super("RATE_LIMITED", "request rate limited, please retry later");
                }
              };
              var S = class extends m {
                constructor() {
                  super("MISSING_PROJECT_ID", "projectId is required when using API token mode. Please supply { name, projectId, token } to getStore() / listStores().");
                }
              };
              var y = class extends m {
                constructor(e) {
                  super("CREDENTIAL_ERROR", e);
                }
              };
              var h = class extends m {
                statusCode;
                constructor(e, n) {
                  super("COS_ERROR", `COS returned ${e}: ${n}`), this.statusCode = e;
                }
              };
              var b = class extends m {
                constructor() {
                  super("PRECONDITION_FAILED", "conditional write failed (key already exists)");
                }
              };
              function C(t) {
                if (t === "")
                  throw new w("Blob key must not be empty.");
                if (t.startsWith("/") || t.startsWith("%2F"))
                  throw new w("Blob key must not start with forward slash (/).");
                if (new TextEncoder().encode(t).length > 600)
                  throw new w("Blob key must be a sequence of Unicode characters whose UTF-8 encoding is at most 600 bytes long.");
              }
              function F(t) {
                if (t === "")
                  throw new p("Store name must not be empty.");
                if (t.includes("/") || t.includes(":"))
                  throw new p("Store name must not contain forward slashes (/) or colons (:).");
                if (!/^[a-zA-Z0-9_-]+$/.test(t))
                  throw new p("Store name must only contain letters, digits, underscores, and hyphens.");
                if (new TextEncoder().encode(t).length > 64)
                  throw new p("Store name must be a sequence of Unicode characters whose UTF-8 encoding is at most 64 bytes long.");
              }
              var T = class {
                cosClient;
                storeName;
                defaultConsistency;
                constructor(e, n, r = "eventual") {
                  this.cosClient = e, this.storeName = n, this.defaultConsistency = r;
                }
                resolveConsistency(e) {
                  return e ?? this.defaultConsistency;
                }
                async set(e, n, r) {
                  C(e);
                  let s = await this.cosClient.putObject(this.storeName, e, n, { onlyIfNew: r == null ? void 0 : r.onlyIfNew, cacheControl: r == null ? void 0 : r.cacheControl });
                  if ((r == null ? void 0 : r.onlyIfNew) && s.statusCode === 412)
                    throw new b();
                }
                async setJSON(e, n, r) {
                  C(e);
                  let s = JSON.stringify(n), o = await this.cosClient.putObject(this.storeName, e, s, { onlyIfNew: r == null ? void 0 : r.onlyIfNew, contentType: "application/json", cacheControl: r == null ? void 0 : r.cacheControl });
                  if ((r == null ? void 0 : r.onlyIfNew) && o.statusCode === 412)
                    throw new b();
                }
                async createUploadUrl(e, n) {
                  C(e);
                  let { url: r, expiresAt: s } = await this.cosClient.createPresignedPutUrl(this.storeName, e, { expireSeconds: n == null ? void 0 : n.expireSeconds, contentType: n == null ? void 0 : n.contentType });
                  return { url: r, key: e, expiresAt: s };
                }
                async get(e, n) {
                  C(e);
                  let r = this.resolveConsistency(n == null ? void 0 : n.consistency), s = await this.cosClient.getObject(this.storeName, e, r);
                  if (s === null)
                    return null;
                  let { body: o } = s, c = (n == null ? void 0 : n.type) ?? "text", i = new TextDecoder("utf-8");
                  switch (c) {
                    case "text":
                      return i.decode(o);
                    case "json":
                      return JSON.parse(i.decode(o));
                    case "arrayBuffer":
                      return o.buffer.slice(o.byteOffset, o.byteOffset + o.byteLength);
                    case "blob":
                      return new Blob([o]);
                    case "stream":
                      return new ReadableStream({ start(d) {
                        d.enqueue(o), d.close();
                      } });
                    default:
                      return i.decode(o);
                  }
                }
                async getMetadata(e, n) {
                  C(e);
                  let r = this.resolveConsistency(n == null ? void 0 : n.consistency);
                  return this.cosClient.headObject(this.storeName, e, r);
                }
                async getWithHeaders(e, n) {
                  C(e);
                  let r = this.resolveConsistency(n == null ? void 0 : n.consistency), s = await this.cosClient.getObject(this.storeName, e, r);
                  return s ? { body: new TextDecoder("utf-8").decode(s.body), headers: s.headers || {} } : null;
                }
                async delete(e) {
                  C(e), await this.cosClient.deleteObject(this.storeName, e);
                }
                async list(e) {
                  let n = (e == null ? void 0 : e.paginate) !== false, r = e == null ? void 0 : e.limit, s = [], o = [], c = this.resolveConsistency(e == null ? void 0 : e.consistency), i = (e == null ? void 0 : e.cursor) || "", d = true, a;
                  for (; d; ) {
                    let l = r !== void 0 ? r - s.length : 1e3, g = Math.min(l, 1e3);
                    if (g <= 0)
                      break;
                    let u = await this.cosClient.listObjects(this.storeName, { prefix: e == null ? void 0 : e.prefix, delimiter: (e == null ? void 0 : e.directories) ? "/" : void 0, marker: i || void 0, maxKeys: g, consistency: c });
                    for (let f of u.contents)
                      s.push({ key: f.key, etag: f.etag });
                    o.push(...u.commonPrefixes), r !== void 0 && s.length >= r ? (s.length = r, (u.isTruncated || u.contents.length === g) && (a = u.nextMarker), d = false) : u.isTruncated ? !n && r === void 0 ? (a = u.nextMarker, d = false) : i = u.nextMarker : d = false;
                  }
                  return { blobs: s, directories: o, ...a ? { cursor: a } : {} };
                }
              };
              var xe = new TextEncoder();
              function K(t) {
                let e = xe.encode(t), n = new ArrayBuffer(e.byteLength), r = new Uint8Array(n);
                return r.set(e), r;
              }
              function V(t) {
                let e = t instanceof Uint8Array ? t : new Uint8Array(t), n = "";
                for (let r = 0; r < e.length; r++)
                  n += e[r].toString(16).padStart(2, "0");
                return n;
              }
              async function W(t, e) {
                let n = await crypto.subtle.importKey("raw", K(t), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]), r = await crypto.subtle.sign("HMAC", n, K(e));
                return V(r);
              }
              async function be(t) {
                let e = await crypto.subtle.digest("SHA-1", K(t));
                return V(e);
              }
              function j(t) {
                return encodeURIComponent(t).replace(/[!'()*]/g, (e) => "%" + e.charCodeAt(0).toString(16).toUpperCase());
              }
              function I(t) {
                try {
                  return decodeURIComponent(t);
                } catch {
                  return t;
                }
              }
              function Ee(t) {
                return t.split("/").map((e) => I(e)).join("/");
              }
              function k(t) {
                return Ee(I(t));
              }
              function J(t) {
                return t.split("/").map((e) => j(I(e))).join("/");
              }
              var Se = /* @__PURE__ */ new Set(["cache-control", "content-disposition", "content-encoding", "content-length", "content-md5", "content-type", "expect", "expires", "if-match", "if-modified-since", "if-none-match", "if-unmodified-since", "origin", "range", "transfer-encoding"]);
              function Te(t) {
                return t === "host" || t === "x-cos-security-token" ? false : !!(Se.has(t) || t.startsWith("x-cos-"));
              }
              function X(t) {
                if (!t)
                  return [];
                let e = [];
                for (let [n, r] of Object.entries(t))
                  r != null && e.push([n.toLowerCase(), String(r)]);
                return e.sort(([n], [r]) => n < r ? -1 : n > r ? 1 : 0), e;
              }
              function Y(t) {
                return t.map(([e, n]) => `${j(e)}=${j(n)}`).join("&");
              }
              function G(t) {
                return t.map(([e]) => j(e)).join(";");
              }
              async function Z(t) {
                let e = t.method.toLowerCase(), n = t.pathname.startsWith("/") ? t.pathname : `/${t.pathname}`, r = Math.floor(Date.now() / 1e3), s = r + (t.expireSeconds ?? 3600), o = `${r};${s}`, i = X(t.headers).filter(([L]) => Te(L)), d = G(i), a = Y(i), l = X(t.query), g = G(l), u = Y(l), f = `${e}
${n}
${u}
${a}
`, _ = `sha1
${o}
${await be(f)}
`, N = await W(t.secretKey, o), de = await W(N, _), le = ["q-sign-algorithm=sha1", `q-ak=${t.secretId}`, `q-sign-time=${o}`, `q-key-time=${o}`, `q-header-list=${d}`, `q-url-param-list=${g}`, `q-signature=${de}`].join("&"), H = {};
                for (let [L, ue] of i)
                  H[L] = ue;
                return { authorization: le, signedHeaders: H };
              }
              async function Q(t) {
                let e = new URL(t.domain), n = I(t.key), r = `/${k(t.key)}`, s = `/${J(n)}`;
                e.pathname = s;
                let { authorization: o } = await Z({ method: t.method, pathname: r, query: t.query, headers: t.headers, secretId: t.credential.secretId, secretKey: t.credential.secretKey, expireSeconds: t.expireSeconds });
                if (t.query)
                  for (let [c, i] of Object.entries(t.query))
                    i != null && e.searchParams.set(c, String(i));
                for (let c of o.split("&")) {
                  let i = c.indexOf("=");
                  if (i === -1)
                    continue;
                  let d = c.slice(0, i), a = c.slice(i + 1);
                  e.searchParams.set(d, a);
                }
                return t.credential.sessionToken && e.searchParams.set("x-cos-security-token", t.credential.sessionToken), e.toString();
              }
              async function P(t) {
                let e = new URL(t.domain), n = t.key ? I(t.key) : "", r = t.key ? `/${k(t.key)}` : "/", s = n ? `/${J(n)}` : "/";
                if (e.pathname = s, t.query)
                  for (let [g, u] of Object.entries(t.query))
                    u != null && e.searchParams.set(g, String(u));
                let { authorization: o } = await Z({ method: t.method, pathname: r, query: t.query, headers: t.headers, secretId: t.credential.secretId, secretKey: t.credential.secretKey }), c = new Headers();
                if (t.headers)
                  for (let [g, u] of Object.entries(t.headers))
                    u != null && c.set(g, String(u));
                c.set("Authorization", o), t.credential.sessionToken && c.set("x-cos-security-token", t.credential.sessionToken);
                let i = e.toString(), d = { method: t.method, headers: c, body: t.body ?? void 0, signal: t.signal }, a = 2, l;
                for (let g = 0; g <= a; g++)
                  try {
                    return await fetch(i, d);
                  } catch (u) {
                    if (l = u, u instanceof DOMException && u.name === "AbortError")
                      throw u;
                    g < a && await new Promise((f) => setTimeout(f, 1e3 * (g + 1)));
                  }
                throw l;
              }
              var Pe = "blob.edgeone.site";
              var Ie = "blob-nocache.edgeone.site";
              var ke = "max-age=0, stale-while-revalidate=60";
              var D = class t {
                credentialManager;
                bucket = "";
                region = "";
                keyPrefix = "";
                cachedDomain = "";
                uncachedDomain = "";
                initialized = false;
                static buildErrorDetail(e, n, r, s, o) {
                  let c = r ? `${n}/${r}` : n, i = o ? ` [request-id: ${o}]` : "";
                  return `${e} ${c} - ${Ae(s)}${i}`;
                }
                constructor(e) {
                  this.credentialManager = e;
                }
                computeSubdomain(e) {
                  let n = [];
                  if (e.appId && n.push(e.appId), e.zoneId && n.push(e.zoneId), e.projectId && n.push(e.projectId), n.length >= 2)
                    return n.join("-");
                  if (e.resourcePrefix) {
                    let s = e.resourcePrefix.replace(/\/?\*$/, "").split("/").filter(Boolean);
                    if (s.length >= 2)
                      return s.slice(0, Math.min(s.length, 3)).join("-");
                  }
                  return "";
                }
                async ensureInitialized() {
                  if (this.initialized)
                    return;
                  let e = await this.credentialManager.getCredential();
                  !this.keyPrefix && e.resourcePrefix && (this.keyPrefix = e.resourcePrefix.replace(/\/?\*$/, ""));
                  let n = e.edgeRegion === "CN", r = e.cosMainland, s = e.cosOverseas, o = n ? r || s : s || r;
                  !this.bucket && o && (this.bucket = o.bucket, this.region = o.region);
                  let { cachedDomain: c, uncachedDomain: i } = e;
                  if (!c || !i) {
                    let d = this.computeSubdomain(e);
                    if (!d)
                      throw new h(0, "unable to derive tenant subdomain from credential; missing appId/zoneId/projectId or resourcePrefix");
                    c || (c = `https://${d}.${Pe}`), i || (i = `https://${d}.${Ie}`);
                  }
                  this.cachedDomain = c, this.uncachedDomain = i, this.initialized = true;
                }
                async resolveDomain(e) {
                  return await this.ensureInitialized(), e === "strong" ? this.uncachedDomain : this.cachedDomain;
                }
                async resolveCredential() {
                  let e = await this.credentialManager.getCredential();
                  return { secretId: e.tmpSecretId, secretKey: e.tmpSecretKey, sessionToken: e.sessionToken };
                }
                buildCosKey(e, n) {
                  return `${this.keyPrefix}/${e}/${n}`;
                }
                async getDomains() {
                  return await this.ensureInitialized(), { cached: this.cachedDomain, uncached: this.uncachedDomain };
                }
                async putObject(e, n, r, s) {
                  let o = await this.resolveDomain("strong"), c = await this.ensureWriteAllowed(), i = await this.resolveCredential(), d = this.buildCosKey(e, n), { defaultCacheControl: a = ke } = c, l = (s == null ? void 0 : s.cacheControl) === null ? void 0 : (s == null ? void 0 : s.cacheControl) ?? a, g = {};
                  (s == null ? void 0 : s.onlyIfNew) && (g["x-cos-forbid-overwrite"] = "true"), l && (g["Cache-Control"] = l), (s == null ? void 0 : s.contentType) && (g["Content-Type"] = s.contentType);
                  let u;
                  try {
                    let f = await P({ domain: o, method: "PUT", key: d, headers: g, body: r, credential: i });
                    if ((s == null ? void 0 : s.onlyIfNew) && (f.status === 409 || f.status === 412))
                      return await f.arrayBuffer().catch(() => {
                      }), { etag: "", statusCode: 412 };
                    if (f.ok) {
                      let N = f.headers.get("etag") || "";
                      return await f.arrayBuffer().catch(() => {
                      }), { etag: N, statusCode: f.status };
                    }
                    let _ = await A(f);
                    u = new h(f.status, t.buildErrorDetail("PUT", o, d, _ || `status ${f.status}`, R(f)));
                  } catch (f) {
                    u = new h(0, t.buildErrorDetail("PUT", o, d, v(f)));
                  }
                  throw await this.explainWriteFailure(u);
                }
                async ensureWriteAllowed() {
                  let e = await this.credentialManager.getCredential();
                  if (e.writeAllowed !== false)
                    return e;
                  let n = e;
                  try {
                    n = await this.credentialManager.refreshCredential();
                  } catch {
                  }
                  return ee(n), n;
                }
                async explainWriteFailure(e) {
                  if (![0, 403, 550].includes(e.statusCode))
                    return e;
                  try {
                    let n = await this.credentialManager.refreshCredential();
                    ee(n);
                  } catch (n) {
                    if (n instanceof x)
                      return n;
                  }
                  return e;
                }
                async createPresignedPutUrl(e, n, r) {
                  let s = await this.resolveDomain("strong");
                  await this.ensureWriteAllowed();
                  let o = await this.resolveCredential(), c = this.buildCosKey(e, n), i = {};
                  (r == null ? void 0 : r.contentType) && (i["Content-Type"] = r.contentType);
                  let d = (r == null ? void 0 : r.expireSeconds) ?? 3600, a = await Q({ domain: s, method: "PUT", key: c, headers: i, credential: o, expireSeconds: d }), l = Math.floor(Date.now() / 1e3) + d;
                  return { url: a, expiresAt: l };
                }
                async getObject(e, n, r) {
                  let s = await this.resolveDomain(r), o = await this.resolveCredential(), c = this.buildCosKey(e, n);
                  try {
                    let i = await P({ domain: s, method: "GET", key: c, credential: o });
                    if (i.status === 404)
                      return await i.arrayBuffer().catch(() => {
                      }), null;
                    if (!i.ok) {
                      let l = await A(i);
                      throw new h(i.status, t.buildErrorDetail("GET", s, c, l || `status ${i.status}`, R(i)));
                    }
                    let d = new Uint8Array(await i.arrayBuffer()), a = te(i.headers);
                    return { body: d, contentType: a["content-type"], headers: a };
                  } catch (i) {
                    throw i instanceof h ? i : new h(0, t.buildErrorDetail("GET", s, c, v(i)));
                  }
                }
                async headObject(e, n, r) {
                  let s = await this.resolveDomain(r), o = await this.resolveCredential(), c = this.buildCosKey(e, n);
                  try {
                    let i = await P({ domain: s, method: "HEAD", key: c, credential: o });
                    if (i.status === 404)
                      return null;
                    if (!i.ok) {
                      let a = await A(i);
                      throw new h(i.status, t.buildErrorDetail("HEAD", s, c, a || `status ${i.status}`, R(i)));
                    }
                    let d = te(i.headers);
                    return { cacheControl: d["cache-control"], contentType: d["content-type"], etag: d.etag, headers: d };
                  } catch (i) {
                    throw i instanceof h ? i : new h(0, t.buildErrorDetail("HEAD", s, c, v(i)));
                  }
                }
                async deleteObject(e, n) {
                  let r = await this.resolveDomain("strong"), s = await this.resolveCredential(), o = this.buildCosKey(e, n);
                  try {
                    let c = await P({ domain: r, method: "DELETE", key: o, credential: s });
                    if (c.status === 204 || c.status === 404 || c.ok) {
                      await c.arrayBuffer().catch(() => {
                      });
                      return;
                    }
                    let i = await A(c);
                    throw new h(c.status, t.buildErrorDetail("DELETE", r, o, i || `status ${c.status}`, R(c)));
                  } catch (c) {
                    throw c instanceof h ? c : new h(0, t.buildErrorDetail("DELETE", r, o, v(c)));
                  }
                }
                async listObjects(e, n) {
                  await this.ensureInitialized();
                  let r = `${this.keyPrefix}/${e}/`, s = (n == null ? void 0 : n.prefix) ? r + n.prefix : r, o = await this.getBucketRaw({ prefix: s, delimiter: n == null ? void 0 : n.delimiter, marker: n == null ? void 0 : n.marker, maxKeys: n == null ? void 0 : n.maxKeys, consistency: n == null ? void 0 : n.consistency }), c = o.contents.map((d) => {
                    let a = d.key, l = a.startsWith(r) ? a.slice(r.length) : a;
                    return l ? { key: l, etag: d.etag } : null;
                  }).filter((d) => d !== null), i = o.commonPrefixes.map((d) => d.startsWith(r) ? d.slice(r.length) : d).filter((d) => !!d);
                  return { contents: c, commonPrefixes: i, isTruncated: o.isTruncated, nextMarker: o.nextMarker };
                }
                async listStores(e) {
                  let n = [], r = "", s = true;
                  for (; s; ) {
                    await this.ensureInitialized();
                    let o = `${this.keyPrefix}/`, c = await this.getBucketRaw({ prefix: o, delimiter: "/", maxKeys: 1e3, marker: r || void 0, consistency: e });
                    for (let i of c.commonPrefixes) {
                      let d = i.startsWith(o) ? i.slice(o.length, -1) : i.slice(0, -1);
                      d && n.push(d);
                    }
                    if (s = c.isTruncated, r = c.nextMarker, !s || !r)
                      break;
                  }
                  return n;
                }
                async getBucketRaw(e) {
                  let n = await this.resolveDomain(e.consistency), r = await this.resolveCredential(), s = { prefix: k(e.prefix) };
                  e.delimiter && (s.delimiter = e.delimiter), e.marker && (s.marker = k(e.marker)), e.maxKeys && (s["max-keys"] = e.maxKeys);
                  try {
                    let o = await P({ domain: n, method: "GET", query: s, credential: r });
                    if (!o.ok) {
                      let i = await A(o);
                      throw new h(o.status, t.buildErrorDetail("LIST", n, e.prefix, i || `status ${o.status}`, R(o)));
                    }
                    let c = await o.text();
                    return Re(c);
                  } catch (o) {
                    throw o instanceof h ? o : new h(0, t.buildErrorDetail("LIST", n, e.prefix, v(o)));
                  }
                }
              };
              function ee(t) {
                if (t.writeAllowed === false)
                  throw new x({ reason: t.writeDeniedReason, overMetrics: t.overMetrics });
              }
              function Ae(t) {
                return t.replace(/[a-zA-Z0-9\-]+\.cos\.[a-zA-Z0-9\-.]+\.myqcloud\.com/gi, "[cos-origin]").replace(/[a-zA-Z0-9\-]+\.cos\.[a-zA-Z0-9\-.]+\.tencentcos\.cn/gi, "[cos-origin]");
              }
              async function A(t) {
                try {
                  return await t.text();
                } catch {
                  return "";
                }
              }
              function R(t) {
                return t.headers.get("x-cos-request-id") || t.headers.get("x-eo-log-id") || void 0;
              }
              function v(t) {
                let e = t, n = e.message || String(t), r = e.cause;
                if (r) {
                  let s = r.message || r.code || "";
                  return s ? `${n} (${s})` : n;
                }
                return n;
              }
              function te(t) {
                let e = {};
                return t.forEach((n, r) => {
                  e[r.toLowerCase()] = n;
                }), e;
              }
              function Re(t) {
                let e = [], n = /<Contents>([\s\S]*?)<\/Contents>/g, r;
                for (; (r = n.exec(t)) !== null; ) {
                  let a = r[1], l = M(a, "Key"), g = M(a, "ETag");
                  l !== null && e.push({ key: q(l), etag: g || "" });
                }
                let s = [], o = /<CommonPrefixes>([\s\S]*?)<\/CommonPrefixes>/g;
                for (; (r = o.exec(t)) !== null; ) {
                  let a = r[1], l = M(a, "Prefix");
                  l !== null && s.push(q(l));
                }
                let i = M(t, "IsTruncated") === "true", d = M(t, "NextMarker") || "";
                return { contents: e, commonPrefixes: s, isTruncated: i, nextMarker: q(d) };
              }
              function M(t, e) {
                let r = new RegExp(`<${e}>([\\s\\S]*?)<\\/${e}>`).exec(t);
                return r ? r[1] : null;
              }
              function q(t) {
                return t.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&");
              }
              var ve = "X-RateLimit-Reset";
              async function $(t, e, n = 2) {
                var _a, _b;
                (_b = (_a = e.signal) == null ? void 0 : _a.throwIfAborted) == null ? void 0 : _b.call(_a);
                try {
                  let r = await fetch(t, e);
                  if (n > 0 && (r.status === 429 || r.status >= 500)) {
                    let s = ne(r.headers.get(ve));
                    return await re(s, e.signal), $(t, e, n - 1);
                  }
                  return r;
                } catch (r) {
                  if (n === 0 || r instanceof DOMException && r.name === "AbortError")
                    throw r;
                  let s = ne();
                  return await re(s, e.signal), $(t, e, n - 1);
                }
              }
              function ne(t) {
                return t ? Math.max(Number(t) * 1e3 - Date.now(), 500) : 1500;
              }
              function re(t, e) {
                return new Promise((n, r) => {
                  if (e == null ? void 0 : e.aborted)
                    return r(e.reason);
                  let s = setTimeout(() => {
                    e == null ? void 0 : e.removeEventListener("abort", o), n();
                  }, t), o = () => {
                    clearTimeout(s), r(e.reason);
                  };
                  e == null ? void 0 : e.addEventListener("abort", o, { once: true });
                });
              }
              var Me = "prod";
              function se() {
                let t = typeof process < "u" ? process.env.PAGES_BLOB_STS_ENV : void 0;
                return t === "test" || t === "prod" ? t : Me;
              }
              var De = 300;
              var Oe = 6e4;
              var Be = "https://blob-sts.edgeone.site/";
              var O = class {
                authToken;
                projectId;
                cached = null;
                lastForcedRefreshAt = 0;
                constructor(e, n) {
                  this.authToken = e, this.projectId = n;
                }
                async getCredential() {
                  if (this.cached && !this.isExpired(this.cached))
                    return this.cached;
                  let e = await this.fetchCredential();
                  return this.cached = e, e;
                }
                async refreshCredential() {
                  if (this.cached && Date.now() - this.lastForcedRefreshAt < Oe)
                    return this.cached;
                  this.lastForcedRefreshAt = Date.now();
                  let e = await this.fetchCredential(true);
                  return this.cached = e, e;
                }
                clearCache() {
                  this.cached = null;
                }
                isExpired(e) {
                  let n = Math.floor(Date.now() / 1e3);
                  return e.expiredTime - n < De;
                }
                async fetchCredential(e = false) {
                  for (let s = 1; s <= 3; s++) {
                    let o = new AbortController(), c = setTimeout(() => o.abort(), 1e4), i;
                    try {
                      i = await $(Be, { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${this.authToken}`, "X-Env": se(), ...e ? { "X-SKIP-CACHE": "true" } : {} }, body: JSON.stringify(this.projectId ? { ProjectId: this.projectId } : {}), signal: o.signal });
                    } catch (l) {
                      if (s < 3) {
                        await z(500 * s);
                        continue;
                      }
                      throw new y(`failed to obtain STS credential: ${l.message || "timeout"}`);
                    } finally {
                      clearTimeout(c);
                    }
                    if (i.status === 413)
                      throw new y("storage quota exceeded");
                    if (i.status === 429)
                      throw new y("rate limited, please retry later");
                    if (!i.ok) {
                      if (i.status >= 500 && s < 3) {
                        await z(500 * s);
                        continue;
                      }
                      let l = await i.text().catch(() => "unknown error");
                      throw new y(`failed to obtain STS credential: ${i.status} ${l}`);
                    }
                    let d = await i.json(), a = d.data && typeof d.data == "object" ? d.data : d;
                    if (a.tmpSecretId && a.tmpSecretKey && a.sessionToken && a.expiredTime) {
                      let l = a.cosMainland, g = a.cosOverseas, u = i.headers.get("X-Edge-Region") || void 0;
                      return { tmpSecretId: a.tmpSecretId, tmpSecretKey: a.tmpSecretKey, sessionToken: a.sessionToken, expiredTime: a.expiredTime, appId: a.appId || void 0, zoneId: a.zoneId || void 0, projectId: a.projectId || void 0, resourcePrefix: a.resourcePrefix || void 0, cosMainland: l || void 0, cosOverseas: g || void 0, edgeRegion: u, defaultCacheControl: typeof a.defaultCacheControl == "string" && a.defaultCacheControl ? a.defaultCacheControl : void 0, cachedDomain: ie(a.cachedDomain), uncachedDomain: ie(a.uncachedDomain), writeAllowed: typeof a.writeAllowed == "boolean" ? a.writeAllowed : void 0, writeDeniedReason: typeof a.writeDeniedReason == "string" && a.writeDeniedReason ? a.writeDeniedReason : void 0, overMetrics: Array.isArray(a.overMetrics) ? a.overMetrics.filter((f) => typeof f == "string") : void 0 };
                    }
                    if (a.code !== void 0 && a.code !== 0) {
                      let l = a.msg || a.message || "unknown error";
                      throw new y(`credential exchange failed (code=${a.code}): ${l}`);
                    }
                    if (d.code !== void 0 && d.code !== 0) {
                      let l = d.msg || d.message || "unknown error";
                      throw new y(`credential exchange failed (code=${d.code}): ${l}`);
                    }
                    if (s < 3) {
                      await z(500 * s);
                      continue;
                    }
                    throw new y("invalid STS credential response");
                  }
                  throw new y("invalid STS credential response");
                }
              };
              function ie(t) {
                if (typeof t != "string")
                  return;
                let e = t.trim().replace(/\/+$/, "");
                if (e)
                  return /^https?:\/\//i.test(e) ? e : `https://${e}`;
              }
              function z(t) {
                return new Promise((e) => setTimeout(e, t));
              }
              var je = "{{PAGES_BLOB_DEPLOY_CREDENTIAL}}";
              function ae() {
                let t = {}, e = $e();
                if (e)
                  t.deployCredential = e;
                else {
                  let r = oe("PAGES_BLOB_DEPLOY_CREDENTIAL");
                  r && (t.deployCredential = r);
                }
                let n = oe("PAGES_PROJECT_ID");
                return n && (t.projectId = n), t;
              }
              function $e() {
                let t = je;
                if (!(t.startsWith("{{") && t.endsWith("}}")))
                  return t || void 0;
              }
              function oe(t) {
                if (typeof process < "u" && process.env)
                  return process.env[t];
              }
              function _e(t) {
                let e = typeof t == "string" ? t : t.name;
                F(e);
                let n = ce(typeof t == "string" ? void 0 : t), r = new O(n.authToken, n.projectId), s = new D(r);
                return new T(s, e, n.consistency ?? "eventual");
              }
              async function Ne(t) {
                let e = ce(t ? { name: "__list__", projectId: t.projectId, token: t.token, consistency: t.consistency } : void 0), n = new O(e.authToken, e.projectId);
                return { stores: (await new D(n).listStores(e.consistency)).map((o) => ({ name: o })) };
              }
              function ce(t) {
                let e = ae(), n = (t == null ? void 0 : t.token) || e.deployCredential, r = (t == null ? void 0 : t.projectId) || e.projectId;
                if ((t == null ? void 0 : t.token) || e.projectId) {
                  if (!r)
                    throw new S();
                  if (!n)
                    throw new E(["token"]);
                  return { authToken: n, projectId: r, consistency: t == null ? void 0 : t.consistency };
                }
                if ((t == null ? void 0 : t.projectId) && !n)
                  throw new E(["token"]);
                if (!e.deployCredential)
                  throw new E(["deployCredential"]);
                return { authToken: e.deployCredential, consistency: t == null ? void 0 : t.consistency };
              }
            }
          });
          var import_pages_blob = __toESM(require_dist());
          var TYPES = {
            jpg: "image/jpeg",
            jpeg: "image/jpeg",
            png: "image/png",
            webp: "image/webp"
          };
          async function onRequest({
            request
          }) {
            if (request.method !== "GET" && request.method !== "HEAD") {
              return new Response("Method Not Allowed", {
                status: 405
              });
            }
            const name = decodeURIComponent(new URL(request.url).pathname.replace(/^\/img\//, ""));
            const ext = name.split(".").pop().toLowerCase();
            if (!/^[a-z0-9._-]+$/i.test(name) || !TYPES[ext]) {
              return new Response("Not Found", {
                status: 404
              });
            }
            const body = await (0, import_pages_blob.getStore)("batik").get("img/" + name, {
              type: "stream"
            });
            if (!body)
              return new Response("Not Found", {
                status: 404
              });
            return new Response(body, {
              headers: {
                "Content-Type": TYPES[ext],
                // dicache di browser & CDN supaya fungsi jarang terpanggil
                "Cache-Control": "public, max-age=604800, s-maxage=2592000"
              }
            });
          }
          return {
            onRequest: typeof onRequest !== "undefined" ? onRequest : void 0,
            onRequestGet: typeof onRequestGet !== "undefined" ? onRequestGet : void 0,
            onRequestPost: typeof onRequestPost !== "undefined" ? onRequestPost : void 0,
            onRequestPut: typeof onRequestPut !== "undefined" ? onRequestPut : void 0,
            onRequestDelete: typeof onRequestDelete !== "undefined" ? onRequestDelete : void 0,
            onRequestPatch: typeof onRequestPatch !== "undefined" ? onRequestPatch : void 0,
            onRequestHead: typeof onRequestHead !== "undefined" ? onRequestHead : void 0,
            onRequestOptions: typeof onRequestOptions !== "undefined" ? onRequestOptions : void 0
          };
        })();
        try {
          const handler = (() => {
            const method = req.method;
            if (method === "GET" && mod_1.onRequestGet) {
              return mod_1.onRequestGet;
            } else if (method === "POST" && mod_1.onRequestPost) {
              return mod_1.onRequestPost;
            } else if (method === "PUT" && mod_1.onRequestPut) {
              return mod_1.onRequestPut;
            } else if (method === "DELETE" && mod_1.onRequestDelete) {
              return mod_1.onRequestDelete;
            } else if (method === "PATCH" && mod_1.onRequestPatch) {
              return mod_1.onRequestPatch;
            } else if (method === "HEAD" && mod_1.onRequestHead) {
              return mod_1.onRequestHead;
            } else if (method === "OPTIONS" && mod_1.onRequestOptions) {
              return mod_1.onRequestOptions;
            } else {
              return mod_1.onRequest;
            }
          })();
          if (handler) {
            response = await __edgeoneWithRestricted(req, () => handler(context));
            if (response && typeof response === "object" && response.websocket) {
              console.log("[WebSocket] WebSocket configuration detected for:", pathname2);
              const upgradeHeader = req.headers["upgrade"];
              if (upgradeHeader && upgradeHeader.toLowerCase() === "websocket") {
                console.log("[WebSocket] Executing WebSocket handshake...");
                try {
                  const { WebSocketServer } = __require("ws");
                  const wss = new WebSocketServer({ noServer: true });
                  wss.on("connection", (ws, request) => {
                    console.log("[WebSocket] Connection established");
                    if (response.websocket.onopen) {
                      try {
                        response.websocket.onopen(ws, request);
                      } catch (error) {
                        console.error("[WebSocket] Error in onopen:", error);
                      }
                    }
                    ws.on("message", (data, isBinary) => {
                      if (response.websocket.onmessage) {
                        try {
                          response.websocket.onmessage(ws, data, isBinary);
                        } catch (error) {
                          console.error("[WebSocket] Error in onmessage:", error);
                          ws.close(1011, "Internal error");
                        }
                      }
                    });
                    ws.on("close", (code, reason) => {
                      if (response.websocket.onclose) {
                        try {
                          response.websocket.onclose(ws, code, reason);
                        } catch (error) {
                          console.error("[WebSocket] Error in onclose:", error);
                        }
                      }
                    });
                    ws.on("error", (error) => {
                      if (response.websocket.onerror) {
                        try {
                          response.websocket.onerror(ws, error);
                        } catch (err) {
                          console.error("[WebSocket] Error in onerror:", err);
                        }
                      } else {
                        console.error("[WebSocket] Connection error:", error);
                      }
                    });
                  });
                  wss.handleUpgrade(req, req.socket, Buffer.alloc(0), (ws) => {
                    wss.emit("connection", ws, req);
                  });
                  console.log("[WebSocket] Handshake complete, connection established");
                  return;
                } catch (wsError) {
                  console.error("[WebSocket] Handshake error:", wsError);
                  response = new Response(JSON.stringify({
                    error: "WebSocket Handshake Failed",
                    message: wsError.message
                  }), {
                    status: 500,
                    headers: {
                      "Content-Type": "application/json"
                    }
                  });
                }
              } else {
                response = new Response("WebSocket endpoint. Use ws:// protocol to connect.", {
                  status: 426,
                  headers: {
                    "Content-Type": "text/plain",
                    "Upgrade": "websocket"
                  }
                });
              }
            }
          }
        } catch (handlerError) {
          console.log("Makers request path: " + fullPath + " |scfRequestId=" + (context.server ? context.server.requestId : "") + "|statusCode=502|");
          response = new Response(JSON.stringify({
            error: "Internal Server Error",
            message: handlerError.message
          }), {
            status: 502,
            headers: {
              "Content-Type": "application/json",
              // 'Functions-Request-Id': context.server ? context.server.requestId : '',
              "eo-pages-inner-scf-status": "502",
              "eo-pages-inner-status-intercept": "true"
            }
          });
        }
        const requestEndTime2 = Date.now();
        console.log("Makers request path: " + fullPath + " |scfRequestId=" + (context.server ? context.server.requestId : "") + "|statusCode=" + String((response == null ? void 0 : response.status) || 200) + "|");
        await handleResponse(res, response, getResponsePassHeaders(context, agentConversationId));
        return;
      }
    }
    if (!response) {
      response = new Response(JSON.stringify({
        error: "Not Found",
        message: "The requested path does not exist"
      }), {
        status: 404,
        headers: {
          "Content-Type": "application/json"
        }
      });
    }
    const requestEndTime = Date.now();
    if (!res.headers) {
      res.headers = {};
    }
    console.log(`Makers request path: ${fullPath} |scfRequestId=${scfRequestId}|statusCode=${(response == null ? void 0 : response.status) || 200}|`);
    await handleResponse(res, response, getResponsePassHeaders(context, agentConversationId));
  } catch (error) {
    console.error("server error", error);
    console.log("Makers request path: " + fullPath + " |scfRequestId=" + (req.headers["x-scf-request-id"] || "") + "|statusCode=502|");
    if (!req.headers["eo-pages-host"] || req.headers["eo-pages-host"] === "localhost:9000" || req.headers["eo-pages-host"] === "undefined" || req.headers["eo-pages-host"] === "null" || req.headers.host === "localhost:9000") {
      console.log(`Makers request info: ${JSON.stringify({
        host: req.headers.host,
        "user-agent": req.headers["user-agent"],
        "eo-pages-host": req.headers["eo-pages-host"],
        "eo-connecting-ip": req.headers["eo-connecting-ip"],
        "x-forwarded-for": req.headers["x-forwarded-for"],
        "x-real-ip": req.headers["x-real-ip"],
        "functions-request-id": req.headers["functions-request-id"],
        path: typeof pathname !== "undefined" ? pathname : void 0,
        url: req.url
      })}`);
    }
    res.writeHead(502, {
      "Content-Type": "application/json",
      "Functions-Request-Id": req.headers["x-scf-request-id"] || "",
      ...agentConversationId ? { [REQUEST_CONVERSATION_ID_HEADER]: agentConversationId } : {},
      "eo-pages-inner-scf-status": "502",
      "eo-pages-inner-status-intercept": "true"
    });
    res.end(JSON.stringify({
      error: "Internal Server Error",
      code: "FUNCTION_INVOCATION_FAILED",
      message: error.message,
      trace: error.stack
    }));
  }
});
server.headersTimeout = 0;
server.requestTimeout = 0;
server.listen(port, () => {
});
export {
  server
};
