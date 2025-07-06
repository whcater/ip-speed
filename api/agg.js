import { refererCheck } from '../common/referer-check.js';
import { Resolver } from 'dns';
import { promisify } from 'util';
import { get } from 'https';
import { isValidIP } from '../common/valid-ip.js';
import countryLookup from 'country-code-lookup';
import maxmind from 'maxmind';
import whoiser from 'whoiser';

// 定义白天模式和黑暗模式样式字符串
const styles = {
    Dark: [
        "feature:all|element:geometry.fill|color:0x242f3e",
        "feature:all|element:labels.text.stroke|color:0x242f3e",
        "feature:all|element:labels.text.fill|color:0x746855",
        "feature:administrative.locality|element:labels.text.fill|color:0xd59563",
        "feature:poi|element:labels.text.fill|color:0xd59563",
        "feature:poi.park|element:geometry|color:0x263c3f",
        "feature:poi.park|element:labels.text.fill|color:0x6b9a76",
        "feature:road|element:geometry|color:0x38414e",
        "feature:road|element:geometry.stroke|color:0x212a37",
        "feature:road|element:labels.text.fill|color:0x9ca5b3",
        "feature:road.highway|element:geometry|color:0x746855",
        "feature:road.highway|element:geometry.stroke|color:0x1f2835",
        "feature:road.highway|element:labels.text.fill|color:0xf3d19c",
        "feature:transit|element:geometry|color:0x2f3948",
        "feature:transit.station|element:labels.text.fill|color:0xd59563",
        "feature:water|element:geometry|color:0x17263c",
        "feature:water|element:labels.text.fill|color:0x515c6d",
        "feature:all|element:labels.text.stroke|color:0x17263c"
    ]
};

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


    // 创建一个用于设置 headers 的通用函数
    function createFetchOptions() {
        return {
            headers: {
                'Authorization': `Bearer ${process.env.CLOUDFLARE_API}`,
                'Content-Type': 'application/json'
            }
        };
    }

    // ASN 信息
    async function getASNInfo(asn) {
        try {
            const url = `https://api.cloudflare.com/client/v4/radar/entities/asns/${asn}`;
            const headers = createFetchOptions().headers;
            const options = { headers };
            const response = await fetch(url, options);
            const json = await response.json();
            return json;
        } catch (error) {
            console.error(error);
            throw new Error('Failed to fetch ASN info');
        }
    };

    // IP 版本分布
    async function getASNIPVersion(asn) {
        try {
            const url = `https://api.cloudflare.com/client/v4/radar/http/summary/ip_version?asn=${asn}&dateRange=7d`;
            const headers = createFetchOptions().headers;
            const options = { headers };
            const response = await fetch(url, options);
            const json = await response.json();
            return json;
        } catch (error) {
            console.error(error);
            throw new Error('Failed to fetch ASN IP version');
        }
    };

    // HTTP 协议分布
    async function getASNHTTPProtocol(asn) {
        try {
            const url = `https://api.cloudflare.com/client/v4/radar/http/summary/http_protocol?asn=${asn}&dateRange=7d`;
            const headers = createFetchOptions().headers;
            const options = { headers };
            const response = await fetch(url, options);
            const json = await response.json();
            return json;
        } catch (error) {
            console.error(error);
            throw new Error('Failed to fetch ASN HTTP protocol');
        }
    };

    // 设备分布
    async function getASNDeviceType(asn) {
        try {
            const url = `https://api.cloudflare.com/client/v4/radar/http/summary/device_type?asn=${asn}&dateRange=7d`;
            const headers = createFetchOptions().headers;
            const options = { headers };
            const response = await fetch(url, options);
            const json = await response.json();
            return json;
        } catch (error) {
            console.error(error);
            throw new Error('Failed to fetch ASN device type');
        }
    };

    // 机器人分布
    async function getASNBotType(asn) {
        try {
            const url = `https://api.cloudflare.com/client/v4/radar/http/summary/bot_class?asn=${asn}&dateRange=7d`;
            const headers = createFetchOptions().headers;
            const options = { headers };
            const response = await fetch(url, options);
            const json = await response.json();
            return json;
        } catch (error) {
            console.error(error);
            throw new Error('Failed to fetch ASN bot type');
        }
    };

    // 验证 asn 是否合法
    function isValidASN(asn) {
        return /^[0-9]+$/.test(asn);
    };


    // 格式化输出

    function formatData(data) {
        const { asnName, asnOrgName, estimatedUsers, IPv4_Pct, IPv6_Pct, HTTP_Pct, HTTPS_Pct, Desktop_Pct, Mobile_Pct, Bot_Pct, Human_Pct } = data;
        const formattedData = {
            asnName,
            asnOrgName,
            estimatedUsers: parseFloat(estimatedUsers).toLocaleString(),
            IPv4_Pct: `${parseFloat(IPv4_Pct).toFixed(2)}%`,
            IPv6_Pct: `${parseFloat(IPv6_Pct).toFixed(2)}%`,
            HTTP_Pct: `${parseFloat(HTTP_Pct).toFixed(2)}%`,
            HTTPS_Pct: `${parseFloat(HTTPS_Pct).toFixed(2)}%`,
            Desktop_Pct: `${parseFloat(Desktop_Pct).toFixed(2)}%`,
            Mobile_Pct: `${parseFloat(Mobile_Pct).toFixed(2)}%`,
            Bot_Pct: `${parseFloat(Bot_Pct).toFixed(2)}%`,
            Human_Pct: `${parseFloat(Human_Pct).toFixed(2)}%`
        };

        return formattedData;

    }

    // 过滤不存在的字段
    function filterData(data) {
        for (const key in data) {
            if (data[key] === 'NaN' || data[key] === 'NaN%') {
                delete data[key];
            }
        }
        return data;
    }

    // 导出函数
    async function cfHander(req, res) {

        // 限制只能从指定域名访问
        const referer = req.headers.referer;
        if (!refererCheck(referer)) {
            return res.status(403).json({ error: referer ? 'Access denied' : 'What are you doing?' });
        }

        const asn = req.query.asn;
        if (!asn) {
            return res.status(400).json({ error: 'No ASN provided' });
        }
        if (!isValidASN(asn)) {
            return res.status(400).json({ error: 'Invalid ASN' });
        }

        try {
            const results = await Promise.allSettled([
                getASNInfo(asn),
                getASNIPVersion(asn),
                getASNHTTPProtocol(asn),
                getASNDeviceType(asn),
                getASNBotType(asn)
            ]);

            // 直接转换每个结果，如果状态是 'fulfilled' 则返回值，否则返回一个包含错误信息的对象
            const response = results.map(result => {
                return result.status === 'fulfilled' ? result.value : { error: 'Failed to fetch data' };
            });

            // 清洗数据
            function cleanUpResponseData(data) {
                return {
                    asnName: data[0]?.result?.asn?.name,
                    asnOrgName: data[0]?.result?.asn?.orgName,
                    estimatedUsers: data[0]?.result?.asn?.estimatedUsers?.estimatedUsers,
                    IPv4_Pct: data[1]?.result?.summary_0?.IPv4,
                    IPv6_Pct: data[1]?.result?.summary_0?.IPv6,
                    HTTP_Pct: data[2]?.result?.summary_0?.http,
                    HTTPS_Pct: data[2]?.result?.summary_0?.https,
                    Desktop_Pct: data[3]?.result?.summary_0?.desktop,
                    Mobile_Pct: data[3]?.result?.summary_0?.mobile,
                    Bot_Pct: data[4]?.result?.summary_0?.bot,
                    Human_Pct: data[4]?.result?.summary_0?.human
                };
            }

            const cleanedResponse = cleanUpResponseData(response);
            const finalResponse = formatData(cleanedResponse);
            filterData(finalResponse);

            res.json(finalResponse);
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Internal server error' });
        }
    }



    // 验证环境变量是否存在，以进行前端功能的开启和关闭
    async function validateConfigs(req, res) {
        // 限制请求方法
        if (req.method !== 'GET') {
            return res.status(405).json({ message: 'Method Not Allowed' });
        }

        // 限制只能从指定域名访问
        const referer = req.headers.referer;
        if (!refererCheck(referer)) {
            return res.status(403).json({ error: referer ? 'Access denied' : 'What are you doing?' });
        }

        const hostname = referer ? new URL(referer).hostname : '';
        const originalSite = hostname === 'ip-speed.hatoolset.com' || hostname === 'localhost';

        const envConfigs = {
            map: process.env.GOOGLE_MAP_API_KEY,
            ipInfo: process.env.IPINFO_API_TOKEN,
            ipChecking: process.env.IPCHECKING_API_KEY,
            keyCDN: process.env.KEYCDN_USER_AGENT,
            originalSite,
            cloudFlare: process.env.CLOUDFLARE_API,
            ipapiis: process.env.IPAPIIS_API_KEY,
        };
        let result = {};
        for (const key in envConfigs) {
            result[key] = !!envConfigs[key];
        }
        res.status(200).json(result);
    };



    // 普通 DNS 服务器列表
    const dnsServers = {
        'Google': '8.8.8.8',
        'Cloudflare': '1.1.1.1',
        'OpenDNS': '208.67.222.222',
        'Quad9': '9.9.9.9',
        'ControlD': '76.76.2.0',
        'AdGuard': '94.140.14.14',
        'Quad 101': '101.101.101.101',
        'AliDNS': '223.5.5.5',
        'DNSPod': '119.29.29.29',
        '114DNS': '114.114.114.114',
        'China Unicom': '123.123.123.123',
    };

    // DNS-over-HTTPS 服务列表
    const dohServers = {
        'Google': 'https://dns.google/resolve?',
        'Cloudflare': 'https://cloudflare-dns.com/dns-query?ct=application/dns-json&',
        'AdGuard': 'https://dns.adguard.com/resolve?',
        'AliDNS': 'https://dns.alidns.com/resolve?',
    };

    const resolveDns = async (hostname, type, name, server) => {
        const resolver = new Resolver();
        resolver.setServers([server]);
        const resolve4Async = promisify(resolver.resolve4.bind(resolver));
        const resolve6Async = promisify(resolver.resolve6.bind(resolver));
        const resolveTxtAsync = promisify(resolver.resolveTxt.bind(resolver));
        const resolveCnameAsync = promisify(resolver.resolveCname.bind(resolver));
        const resolveNSAsync = promisify(resolver.resolveNs.bind(resolver));
        const resolveMXAsync = promisify(resolver.resolveMx.bind(resolver));
        try {
            let addresses;

            // 根据传入的 type 参数选择不同的解析方法
            switch (type) {
                case 'A':
                    addresses = await resolve4Async(hostname);
                    break;
                case 'AAAA':
                    addresses = await resolve6Async(hostname);
                    break;
                case 'TXT':
                    addresses = await resolveTxtAsync(hostname);
                    // TXT 记录解析的结果是一个二维数组，这里进行扁平化处理
                    addresses = addresses.flat();
                    break;
                case 'CNAME':
                    addresses = await resolveCnameAsync(hostname);
                    break;
                case 'NS':
                    addresses = await resolveNSAsync(hostname);
                    break;
                case 'MX':
                    addresses = await resolveMXAsync(hostname);
                    addresses = addresses.map(item => `${item.priority} ${item.exchange}.`)
                        .join(', ');
                    break;
                default:
                    throw new Error('Unsupported type');
            }

            if (addresses.length === 0 || addresses === '' || addresses === null) {
                return { [name]: `N/A` };
            }

            return { [name]: addresses };
        } catch (error) {
            console.log(error.message);
            return { [name]: `N/A` };
        }
    };

    const resolveDoh = async (hostname, type, name, url) => {
        try {
            const response = await fetch(`${url}name=${hostname}&type=${type}`, {
                headers: { 'Accept': 'application/dns-json' }
            });
            const data = await response.json();
            const addresses = data.Answer ? data.Answer.map(answer => answer.data) : ['N/A'];
            if (addresses.length === 0 || addresses === '' || addresses === null) {
                return { [name]: `N/A` };
            }
            return { [name]: addresses };
        } catch (error) {
            console.log(error.message);
            return { [name]: `N/A` };
        }
    };

    const dnsResolver = async (req, res) => {

        // 限制请求方法
        if (req.method !== 'GET') {
            return res.status(405).json({ message: 'Method Not Allowed' });
        }

        // 限制只能从指定域名访问
        const referer = req.headers.referer;
        if (!refererCheck(referer)) {
            return res.status(403).json({ error: referer ? 'Access denied' : 'What are you doing?' });
        }

        const { hostname, type } = req.query;

        if (typeof hostname !== 'string') {
            return res.status(400).send({ error: 'Hostname parameter must be a string' });
        }

        if (!hostname) {
            return res.status(400).send({ error: 'Missing hostname parameter' });
        }

        if (!hostname.includes('.')) {
            return res.status(400).send({ error: 'Invalid hostname' });
        }

        const dnsPromises = Object.entries(dnsServers).map(([name, ip]) => resolveDns(hostname, type, name, ip));
        const dohPromises = Object.entries(dohServers).map(([name, url]) => resolveDoh(hostname, type, name, url));

        try {
            // 并行执行所有 DNS 和 DoH 查询

            const result_dns = await Promise.all(dnsPromises);
            const result_doh = await Promise.all(dohPromises);

            res.json({
                hostname,
                result_dns,
                result_doh
            });
        } catch (error) {
            res.status(500).send({ error: error.message });
        }
    };



    // 如果长度不等于 28 且不是字母与数字的组合，则返回 false
    function isValidUserID(userID) {
        if (typeof userID !== 'string') {
            console.error("Invalid type for userID");
            return false;
        }
        if (userID.length !== 28 || !/^[a-zA-Z0-9]+$/.test(userID)) {
            console.error("Invalid userID format");
            return false;
        }
        return true;
    }

    async function invisibilitytestHandler(req, res) {

        // 限制只能从指定域名访问
        const referer = req.headers.referer;
        if (!refererCheck(referer)) {
            return res.status(403).json({ error: referer ? 'Access denied' : 'What are you doing?' });
        }

        const id = req.query.id;
        if (!id) {
            return res.status(400).json({ error: 'No ID provided' });
        }

        // 检查 IP 地址是否合法
        if (!isValidUserID(id)) {
            return res.status(400).json({ error: 'Invalid ID' });
        }

        const apikey = process.env.IPCHECKING_API_KEY;

        if (!apikey) {
            return res.status(500).json({ error: 'API key is missing' });
        }

        const url = new URL(`https://api.ipcheck.ing/getpdresult/${id}?apikey=${apikey}`);

        get(url, apiRes => {
            let data = '';
            apiRes.on('data', chunk => data += chunk);
            apiRes.on('end', () => {
                try {
                    const result = JSON.parse(data);
                    res.json(result);
                } catch (e) {
                    res.status(500).json({ error: 'Error parsing JSON' });
                }
            });
        }).on('error', (e) => {
            res.status(500).json({ error: e.message });
        });
    };




    async function ipapicomHandler(req, res) {
        // 限制只能从指定域名访问
        const referer = req.headers.referer;
        if (!refererCheck(referer)) {
            return res.status(403).json({ error: referer ? 'Access denied' : 'What are you doing?' });
        }

        // 从请求中获取 IP 地址
        const ipAddress = req.query.ip;
        if (!ipAddress) {
            return res.status(400).json({ error: 'No IP address provided' });
        }

        // 检查 IP 地址是否合法
        if (!isValidIP(ipAddress)) {
            return res.status(400).json({ error: 'Invalid IP address' });
        }

        // 构建请求 ip-api.com 的 URL
        const lang = req.query.lang || 'en';
        const url = `http://ip-api.com/json/${ipAddress}?fields=66842623&lang=${lang}`;

        get(url, apiRes => {
            let data = '';
            apiRes.on('data', chunk => data += chunk);
            apiRes.on('end', () => {
                try {
                    const originalJson = JSON.parse(data);
                    const modifiedJson = modifyJsonForIPAPICOM(originalJson);
                    res.json(modifiedJson);
                } catch (e) {
                    res.status(500).json({ error: 'Error parsing JSON' });
                }
            });
        }).on('error', (e) => {
            res.status(500).json({ error: e.message });
        });
    };

    function modifyJsonForIPAPICOM(json) {
        const { query, country, countryCode, regionName, city, lat, lon, isp, as } = json;
        const asn = as ? as.split(" ")[0] : '';

        return {
            ip: query,
            city,
            region: regionName,
            country: countryCode,
            country_name: country,
            country_code: countryCode,
            latitude: lat,
            longitude: lon,
            asn,
            org: isp
        };
    }



    async function ipapiisHandler(req, res) {
        // 限制只能从指定域名访问
        const referer = req.headers.referer;
        if (!refererCheck(referer)) {
            return res.status(403).json({ error: referer ? 'Access denied' : 'What are you doing?' });
        }


        // 从请求中获取 IP 地址
        const ipAddress = req.query.ip;
        if (!ipAddress) {
            return res.status(400).json({ error: 'No IP address provided' });
        }

        // 检查 IP 地址是否合法
        if (!isValidIP(ipAddress)) {
            return res.status(400).json({ error: 'Invalid IP address' });
        }

        const keys = (process.env.IPAPIIS_API_KEY).split(',');
        const key = keys[Math.floor(Math.random() * keys.length)];
        const url = `https://api.ipapi.is?q=${ipAddress}&key=${key}`;

        get(url, apiRes => {
            let data = '';
            apiRes.on('data', chunk => data += chunk);
            apiRes.on('end', () => {
                try {
                    const originalJson = JSON.parse(data);
                    const modifiedJson = modifyJsonForIPAPIIS(originalJson);
                    res.json(modifiedJson);
                } catch (e) {
                    res.status(500).json({ error: 'Error parsing JSON' });
                }
            });
        }).on('error', (e) => {
            res.status(500).json({ error: e.message });
        });
    };

    function modifyJsonForIPAPIIS(json) {
        let asn = json.asn || {};
        const { ip, location, is_datacenter, is_proxy, is_vpn, is_tor } = json;

        return {
            ip: ip,
            city: location.city || 'N/A',
            region: location.state || 'N/A',
            country: location.country_code || 'N/A',
            country_name: location.country || 'N/A',
            country_code: location.country_code || 'N/A',
            latitude: location.latitude || 'N/A',
            longitude: location.longitude || 'N/A',
            asn: asn.asn === undefined ? 'N/A' : 'AS' + asn.asn,
            org: asn.org || 'N/A',
            isHosting: is_datacenter || false,
            isProxy: is_proxy || is_vpn || is_tor || false
        };
    }




    async function ipCheckingHandler(req, res) {

        // 限制只能从指定域名访问
        const referer = req.headers.referer;
        if (!refererCheck(referer)) {
            return res.status(403).json({ error: referer ? 'Access denied' : 'What are you doing?' });
        }


        // 从请求中获取 IP 地址
        const ipAddress = req.query.ip;
        if (!ipAddress) {
            return res.status(400).json({ error: 'No IP address provided' });
        }

        // 检查 IP 地址是否合法
        if (!isValidIP(ipAddress)) {
            return res.status(400).json({ error: 'Invalid IP address' });
        }

        const key = process.env.IPCHECKING_API_KEY;

        if (!key) {
            return res.status(500).json({ error: 'API key is missing' });
        }

        const lang = req.query.lang || 'en';

        // 构建请求 IPCheck.ing 的 URL
        const url = new URL(`https://api.ipcheck.ing/ipinfo?key=${key}&ip=${ipAddress}&lang=${lang}`);

        get(url, apiRes => {
            let data = '';
            apiRes.on('data', chunk => data += chunk);
            apiRes.on('end', () => {
                try {
                    const originalJson = JSON.parse(data);
                    res.json(originalJson);
                } catch (e) {
                    res.status(500).json({ error: 'Error parsing JSON' });
                }
            });
        }).on('error', (e) => {
            res.status(500).json({ error: e.message });
        });
    }


    async function ipinfoHandler(req, res) {
        // 限制只能从指定域名访问
        const referer = req.headers.referer;
        if (!refererCheck(referer)) {
            return res.status(403).json({ error: referer ? 'Access denied' : 'What are you doing?' });
        }

        // 从请求中获取 IP 地址
        const ipAddress = req.query.ip;
        if (!ipAddress) {
            return res.status(400).json({ error: 'No IP address provided' });
        }

        // 检查 IP 地址是否合法
        if (!isValidIP(ipAddress)) {
            return res.status(400).json({ error: 'Invalid IP address' });
        }

        // 构建请求 ipinfo.io 的 URL
        const tokens = (process.env.IPINFO_API_TOKEN || '').split(',');
        const token = tokens[Math.floor(Math.random() * tokens.length)];

        const url_hasToken = `https://ipinfo.io/${ipAddress}?token=${token}`;
        const url_noToken = `https://ipinfo.io/${ipAddress}`;
        const url = token ? url_hasToken : url_noToken;

        get(url, apiRes => {
            let data = '';
            apiRes.on('data', chunk => data += chunk);
            apiRes.on('end', async () => {
                try {
                    const originalJson = JSON.parse(data);
                    const modifiedJson = modifyJson(originalJson);

                    res.json(modifiedJson);
                } catch (e) {
                    res.status(500).json({ error: 'Error parsing JSON' });
                }
            });
        }).on('error', (e) => {
            res.status(500).json({ error: e.message });
        });
    };

    function modifyJson(json) {
        const { ip, city, region, country, loc, org } = json;

        const countryName = countryLookup.byIso(country).country || 'Unknown Country';

        const [latitude, longitude] = loc.split(',').map(Number);
        const [asn, ...orgName] = org.split(' ');
        const modifiedOrg = orgName.join(' ');

        return {
            ip,
            city,
            region,
            country,
            country_name: countryName,
            country_code: country,
            latitude,
            longitude,
            asn,
            org: modifiedOrg
        };
    }




    async function ipsbHandler(req, res) {

        // 限制只能从指定域名访问
        const referer = req.headers.referer;
        if (!refererCheck(referer)) {
            return res.status(403).json({ error: referer ? 'Access denied' : 'What are you doing?' });
        }

        const ipAddress = req.query.ip;
        if (!ipAddress) {
            return res.status(400).json({ error: 'No IP address provided' });
        }

        // 检查 IP 地址是否合法
        if (!isValidIP(ipAddress)) {
            return res.status(400).json({ error: 'Invalid IP address' });
        }

        const url = new URL(`https://api.ip.sb/geoip/${ipAddress}`);

        get(url, apiRes => {
            let data = '';
            apiRes.on('data', chunk => data += chunk);
            apiRes.on('end', () => {
                try {
                    const originalJson = JSON.parse(data);
                    const modifiedJson = modifyJsonForIPSB(originalJson);
                    res.json(modifiedJson);
                } catch (e) {
                    res.status(500).json({ error: 'Error parsing JSON' });
                }
            });
        }).on('error', (e) => {
            res.status(500).json({ error: e.message });
        });
    };

    function modifyJsonForIPSB(json) {
        return {
            ip: json.ip,
            city: json.city,
            region: json.region ? json.region : json.city,
            country: json.country_code,
            country_name: json.country,
            country_code: json.country_code,
            latitude: json.latitude,
            longitude: json.longitude,
            asn: "AS" + json.asn,
            org: json.isp
        };
    }


    async function keycdnHandler(req, res) {
        // 限制只能从指定域名访问
        const referer = req.headers.referer;
        if (!refererCheck(referer)) {
            return res.status(403).json({ error: referer ? 'Access denied' : 'What are you doing?' });
        }


        // 从请求中获取 IP 地址
        const ipAddress = req.query.ip;
        if (!ipAddress) {
            return res.status(400).json({ error: 'No IP address provided' });
        }

        // 检查 IP 地址是否合法
        if (!isValidIP(ipAddress)) {
            return res.status(400).json({ error: 'Invalid IP address' });
        }

        // 构建请求 keycdn.com 的 URL
        const url = new URL(`https://tools.keycdn.com/geo.json?host=${ipAddress}`);

        // 设置请求选项，包括 User-Agent
        const options = {
            hostname: url.hostname,
            path: url.pathname + url.search,
            headers: {
                'User-Agent': 'keycdn-tools:' + process.env.KEYCDN_USER_AGENT
            }
        };

        get(options, apiRes => {
            let data = '';
            apiRes.on('data', chunk => data += chunk);
            apiRes.on('end', () => {
                try {
                    const originalJson = JSON.parse(data);
                    const modifiedJson = modifyJsonForKeyCDN(originalJson);
                    res.json(modifiedJson);
                } catch (e) {
                    res.status(500).json({ error: 'Error parsing JSON' });
                }
            });
        }).on('error', (e) => {
            res.status(500).json({ error: e.message });
        });
    }

    function modifyJsonForKeyCDN(json) {
        const { data: { geo: { ip, city, region_name, country_name, country_code, latitude, longitude, isp, asn } } } = json;

        return {
            ip,
            city,
            region: region_name ? region_name : city,
            country: country_code,
            country_name,
            country_code,
            latitude,
            longitude,
            asn: "AS" + asn,
            org: isp
        };
    }




    const isValidMAC = (address) => {
        const normalizedAddress = address.replace(/[:-]/g, '');
        return normalizedAddress.length >= 6 && normalizedAddress.length <= 12 && /^[0-9A-Fa-f]+$/.test(normalizedAddress);
    }

    async function macChecker(req, res) {
        // 限制只能从指定域名访问
        const referer = req.headers.referer;
        if (!refererCheck(referer)) {
            return res.status(403).json({ error: referer ? 'Access denied' : 'What are you doing?' });
        }

        // 从请求中获取 IP 地址
        let macAddress = req.query.mac;
        if (!macAddress) {
            return res.status(400).json({ error: 'No MAC address provided' });
        } else {
            macAddress = macAddress.replace(/:/g, '').replace(/-/g, '');
        }

        // 检查 IP 地址是否合法
        if (!isValidMAC(macAddress)) {
            return res.status(400).json({ error: 'Invalid MAC address' });
        }


        const token = process.env.MAC_LOOKUP_API_KEY || '';

        const url_hasToken = `https://api.maclookup.app/v2/macs/${macAddress}?apiKey=${token}`;
        const url_noToken = `https://api.maclookup.app/v2/macs/${macAddress}`;
        const url = token ? url_hasToken : url_noToken;

        get(url, apiRes => {
            let data = '';
            apiRes.on('data', chunk => data += chunk);
            apiRes.on('end', async () => {
                try {
                    const originalJson = JSON.parse(data);
                    if (originalJson.success !== true) {
                        return res.json({ success: false, error: originalJson.error || 'Data not found' });
                    }
                    const finalData = modifyData(originalJson);
                    res.json(finalData);
                } catch (e) {
                    res.status(500).json({ error: 'Error parsing JSON' });
                }
            });
        }).on('error', (e) => {
            res.status(500).json({ error: e.message });
        });
    };


    function modifyData(data) {
        // 检查单播/多播以及本地/全球地址
        const firstByte = parseInt(data.macPrefix.substring(0, 2), 16);
        const isMulticast = (firstByte & 0x01) === 0x01;
        const isLocal = (firstByte & 0x02) === 0x02;

        data.isMulticast = isMulticast ? true : false;
        data.isLocal = isLocal ? true : false;
        data.isGlobal = !isLocal ? true : false;
        data.isUnicast = !isMulticast ? true : false;
        data.macPrefix = data.macPrefix ? data.macPrefix.match(/.{1,2}/g).join(':') : 'N/A';
        data.company = data.company ? data.company : 'N/A';
        data.country = data.country ? data.country : 'N/A';
        data.address = data.address ? data.address : 'N/A';
        data.updated = data.updated ? data.updated : 'N/A';
        data.blockStart = data.blockStart ? data.blockStart.match(/.{1,2}/g).join(':') : 'N/A';
        data.blockEnd = data.blockEnd ? data.blockEnd.match(/.{1,2}/g).join(':') : 'N/A';
        data.blockSize = data.blockSize ? data.blockSize : 'N/A';
        data.blockType = data.blockType ? data.blockType : 'N/A';

        return data;
    }




    // 验证请求合法性
    function isValidRequest(req) {
        const isLatitudeValid = /^-?\d+(\.\d+)?$/.test(req.query.latitude);
        const isLongitudeValid = /^-?\d+(\.\d+)?$/.test(req.query.longitude);
        const isLanguageValid = /^[a-z]{2}$/.test(req.query.language);

        if (!isLatitudeValid || !isLongitudeValid || !isLanguageValid) {
            return false;
        } else {
            return true;
        }
    }

    async function mapHandler(req, res) {
        // 限制只能从指定域名访问
        const referer = req.headers.referer;
        if (!refererCheck(referer)) {
            return res.status(403).json({ error: referer ? 'Access denied' : 'What are you doing?' });
        }

        // 检查请求是否合法
        if (!isValidRequest(req)) {
            return res.status(400).json({ error: 'Invalid request' });
        }

        // 使用 req.query 获取参数
        const { latitude, longitude, language, CanvasMode } = req.query;

        if (!latitude || !longitude || !language) {
            return res.status(400).json({ error: 'Missing latitude, longitude, or language' });
        }

        const mapSize = '500x400';
        const fmt = 'jpg';
        const scale = 2;
        const zoom = 3;

        const apiKeys = (process.env.GOOGLE_MAP_API_KEY || '').split(',');
        const apiKey = apiKeys[Math.floor(Math.random() * apiKeys.length)];

        let styleParam = '';
        if (CanvasMode === 'Dark') {
            styleParam = styles.Dark.join('&style=');
        }

        const url = `https://maps.googleapis.com/maps/api/staticmap?center=${latitude},${longitude}&markers=color:blue%7C${latitude},${longitude}&scale=${scale}&zoom=${zoom}&maptype=roadmap&language=${language}&format=${fmt}&size=${mapSize}&style=${styleParam}&key=${apiKey}`;

        get(url, apiRes => {
            apiRes.pipe(res);
        }).on('error', (e) => {
            res.status(500).json({ error: e.message });
        });
    };



    let cityLookup, asnLookup;

    // 异步初始化数据库
    async function initDatabases() {
        cityLookup = await maxmind.open('GeoLite2-City.mmdb');
        asnLookup = await maxmind.open('GeoLite2-ASN.mmdb');
    }

    initDatabases();

    async function maxmindHandler(req, res) {

        // 限制只能从指定域名访问
        const referer = req.headers.referer;
        if (!refererCheck(referer)) {
            return res.status(403).json({ error: referer ? 'Access denied' : 'What are you doing?' });
        }

        const ip = req.query.ip;
        if (!ip) {
            return res.status(400).json({ error: 'No IP address provided' });
        }

        // 检查 IP 地址是否合法
        if (!isValidIP(ip)) {
            return res.status(400).json({ error: 'Invalid IP address' });
        }

        // 获取请求语言
        const lang = req.query.lang === 'zh-CN' || req.query.lang === 'en' || req.query.lang === 'fr' ? req.query.lang : 'en';

        try {
            const city = cityLookup.get(ip);
            const asn = asnLookup.get(ip);
            let result = modifyJson(ip, lang, city, asn);
            res.json(result);
        } catch (e) {
            res.status(500).json({ error: e.message });
        }
    }

    function modifyJson(ip, lang, city, asn) {
        city = city || {};
        asn = asn || {};
        return {
            ip,
            city: city.city ? city.city.names[lang] || city.city.names.en : "N/A",
            region: city.subdivisions ? city.subdivisions[0].names[lang] || city.subdivisions[0].names.en : "N/A",
            country: city.country ? city.country.iso_code : "N/A",
            country_name: city.country ? city.country.names[lang] : "N/A",
            country_code: city.country ? city.country.iso_code : "N/A",
            latitude: city.location ? city.location.latitude : "N/A",
            longitude: city.location ? city.location.longitude : "N/A",
            asn: asn.autonomous_system_number ? "AS" + asn.autonomous_system_number : "N/A",
            org: asn.autonomous_system_organization ? asn.autonomous_system_organization : "N/A"
        };
    };




    function isValidDomain(domain) {
        const domainPattern = /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i;
        return domainPattern.test(domain);
    }

    async function whois(req, res) {
        // 限制只能从指定域名访问
        const referer = req.headers.referer;
        if (!refererCheck(referer)) {
            return res.status(403).json({ error: referer ? 'Access denied' : 'What are you doing?' });
        }


        const query = req.query.q;
        if (!query) {
            return res.status(400).json({ error: 'No address provided' });
        }

        // 检查 IP 地址是否合法
        if (!isValidIP(query) && !isValidDomain(query)) {
            return res.status(400).json({ error: 'Invalid IP or address' });
        }

        if (isValidIP(query)) {
            try {
                const ipinfo = await whoiser.ip(query, { timeout: 5000, raw: true });
                res.json(ipinfo);
            } catch (e) {
                res.status(500).json({ error: e.message });
            }
        } else {
            try {
                const domaininfo = await whoiser.domain(query, { ignorePrivacy: false, timeout: 5000, follow: 2, raw: true });
                res.json(domaininfo);
            } catch (e) {
                res.status(500).json({ error: e.message });
            }
        }
    };
} 