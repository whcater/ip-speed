import mapHandler from './map.js';
import ipinfoHandler from './ipinfo.js';
import ipapicomHandler from './ipapicom.js';
import keycdnHandler from './keycdn.js';
import ipCheckingHandler from './ipchecking.js';
import ipsbHandler from './ipsb.js';
import cfHander from './cfradar.js';
import validateConfigs from './configs.js';
import dnsResolver from './dnsresolver.js';
import whois from './whois.js';
import ipapiisHandler from './ipapiis.js';
import invisibilitytestHandler from './invisibilitytest.js';
import macChecker from './macchecker.js';
import maxmindHandler from './maxmind.js';

// 获取客户端真实IP地址
function getClientIp(req) {
    const cfIp = req.headers['cf-connecting-ip']; // Cloudflare IP
    const cfIpV6 = req.headers['cf-connecting-ipv6']; // Cloudflare IPv6
    const forwardedIps = req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0].trim() : null;
    const realIp = req.headers['x-real-ip'];
    
    return cfIp || cfIpV6 || forwardedIps || realIp || req.ip || req.connection.remoteAddress || req.socket.remoteAddress;
}

// 处理客户端IP请求
function handleClientIP(req, res) {
    const clientIp = getClientIp(req);
    const isIPv6 = clientIp && clientIp.includes(':');
    
    return res.json({
        ip: clientIp,
        type: isIPv6 ? 'IPv6' : 'IPv4',
        timestamp: Date.now()
    });
}

// 处理trace请求 - 类似于/cdn-cgi/trace
function handleTrace(req, res) {
    const clientIp = getClientIp(req);
    const timestamp = (Date.now() / 1000).toFixed(3);
    const userAgent = req.headers['user-agent'] || '';
    const host = req.headers.host || '';
    const protocol = req.protocol || 'http';
    const httpVersion = req.httpVersion || '1.1';
    
    // 生成类似于Cloudflare trace的响应
    const traceData = [
        `fl=${Math.random().toString(36).substr(2, 8)}`, // 随机标识符
        `h=${host}`,
        `ip=${clientIp}`,
        `ts=${timestamp}`,
        `visit_scheme=${protocol}`,
        `uag=${userAgent}`,
        `colo=LOCAL`, // 本地部署
        `sliver=none`,
        `http=http/${httpVersion}`,
        `loc=LOCAL`, // 本地位置
        `tls=${protocol === 'https' ? 'TLSv1.3' : 'off'}`,
        `sni=plaintext`,
        `warp=off`,
        `gateway=off`,
        `rbi=off`,
        `kex=X25519`
    ].join('\n');
    
    return res.set('Content-Type', 'text/plain').send(traceData);
}

// 聚合API处理函数
export default async function aggregateHandler(req, res) {
    try {
        // 确保是POST请求
        if (req.method !== 'POST') {
            return res.status(405).json({ error: 'Method not allowed' });
        }

        // 获取请求体
        const { eventName, ...params } = req.body;

        if (!eventName) {
            return res.status(400).json({ error: 'eventName is required' });
        }

        // 创建一个新的请求对象，模拟原来的GET请求
        const mockReq = {
            ...req,
            method: 'GET',
            query: params,
            headers: req.headers, // 确保headers被正确传递
            ip: req.ip,
            ips: req.ips,
            connection: req.connection,
            socket: req.socket,
        };

        // 根据eventName路由到对应的处理函数
        switch (eventName) {
            case '/api/map':
                return await mapHandler(mockReq, res);
            case '/api/ipinfo':
                return await ipinfoHandler(mockReq, res);
            case '/api/ipapicom':
                return await ipapicomHandler(mockReq, res);
            case '/api/keycdn':
                return await keycdnHandler(mockReq, res);
            case '/api/ipchecking':
                return await ipCheckingHandler(mockReq, res);
            case '/api/ipsb':
                return await ipsbHandler(mockReq, res);
            case '/api/cfradar':
                return await cfHander(mockReq, res);
            case '/api/dnsresolver':
                return await dnsResolver(mockReq, res);
            case '/api/whois':
                return await whois(mockReq, res);
            case '/api/ipapiis':
                return await ipapiisHandler(mockReq, res);
            case '/api/invisibility':
                return await invisibilitytestHandler(mockReq, res);
            case '/api/macchecker':
                return await macChecker(mockReq, res);
            case '/api/maxmind':
                return await maxmindHandler(mockReq, res);
            case '/api/configs':
                return await validateConfigs(mockReq, res);
            case '/api/clientip':
                return handleClientIP(req, res);
            case '/api/trace':
                return handleTrace(req, res);
            default:
                return res.status(404).json({ error: 'Unknown eventName: ' + eventName });
        }
    } catch (error) {
        console.error('Error in aggregate handler:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
} 