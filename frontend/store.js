// store.js
import { defineStore } from 'pinia';

export const useMainStore = defineStore('main', {

  state: () => ({
    lang: 'en',
    currentPath: {},
    mountingStatus: {
      ipcheck: false,
      connectivity: false,
      webrtc: false,
      dnsleaktest: false,
      speedtest: false,
      advancedtools: false,
    },
    shell: {
      ipv4Domain: import.meta.env.VITE_CURL_IPV4_DOMAIN,
      ipv6Domain: import.meta.env.VITE_CURL_IPV6_DOMAIN,
      ipv64Domain: import.meta.env.VITE_CURL_IPV64_DOMAIN,
    },
    loadingStatus: {
      ipcheck: false,
      connectivity: false,
      webrtc: false,
      dnsleaktest: false,
    },
    isDarkMode: false,
    isMobile: false,
    shouldRefreshEveryThing: false,
    allIPs: [],
    configs: {},
    userPreferences: {},
    alert: {
      alertToShow: false,
      alertStyle: "",
      alertMessage: "",
      alertTitle: "",
    },
    ipDBs: [
      { id: 0, text: 'IPCheck.ing', eventName: '/api/ipchecking', enabled: true },
      { id: 1, text: 'IPinfo.io', eventName: '/api/ipinfo', enabled: true },
      { id: 2, text: 'IP-API.com', eventName: '/api/ipapicom', enabled: true },
      { id: 3, text: 'IPAPI.co', url: 'https://ipapi.co/{{ip}}/json/', enabled: true },
      { id: 4, text: 'KeyCDN', eventName: '/api/keycdn', enabled: true },
      { id: 5, text: 'IP.SB', eventName: '/api/ipsb', enabled: true },
      { id: 6, text: 'IPAPI.is', eventName: '/api/ipapiis', enabled: true },
      { id: 7, text: 'MaxMind', eventName: '/api/maxmind', enabled: true },
    ],
  }),

  getters: {
    activeSources: (state) => state.ipDBs.filter(db => db.enabled),
    allHasLoaded: (state) => {
      return Object.values(state.loadingStatus).every(status => status);
    },
    curlDomainsHadSet: (state) => {
      return state.shell.ipv4Domain && state.shell.ipv6Domain && state.shell.ipv64Domain;
    }
  },

  actions: {
    // 设置当前 route 路径
    setCurrentPath(path, id) {
      this.currentPath = { path: path, id: id };
    },
    // 获取数据库的URL（保留外部API的原有方式）
    getDbUrl(id, ip, lang) {
      const db = this.ipDBs.find(d => d.id === id);
      if (!db) return null;
      // 对于外部API（如IPAPI.co），保持原有的URL方式
      if (db.url) {
        return db.url.replace('{{ip}}', ip).replace('{{lang}}', lang || 'en');
      }
      // 对于内部API，返回null，将使用aggregateApiFetch方法
      return null;
    },
    // 使用聚合API获取数据
    async aggregateApiFetch(eventName, params = {}) {
      try {
        const response = await fetch('/api/agg', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            eventName,
            ...params
          })
        });
        
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return await response.json();
      } catch (error) {
        console.error('Error in aggregateApiFetch:', error);
        throw error;
      }
    },
    // 从每个组件返回启动状态
    setMountingStatus(key, value) {
      this.mountingStatus[key] = value;
    },
    // 从每个组件返回加载状态
    setLoadingStatus(key, value) {
      this.loadingStatus[key] = value;
    },
    // 设置 Toast
    setAlert(alertToShow, alertStyle, alertMessage, alertTitle) {
      this.alert = { alertToShow, alertStyle, alertMessage, alertTitle };
    },
    // 从不同的组件收集合并 IP 数据
    updateAllIPs(payload) {
      const uniqueIPs = new Set([...this.allIPs, ...payload]);
      this.allIPs = Array.from(uniqueIPs);
    },
    // 设置移动模式
    setIsMobile(payload) {
      this.isMobile = payload;
    },
    // App.vue 和 Nav.vue 的通信辅助函数
    setRefreshEveryThing(payload) {
      this.shouldRefreshEveryThing = payload;
    },
    // 设置黑暗模式
    setDarkMode(value) {
      this.isDarkMode = value;
    },
    // 设置 IP 数据库的使能状态
    updateIPDBs({ id, enabled }) {
      const index = this.ipDBs.findIndex(db => db.id === id);
      if (index !== -1) {
        this.ipDBs[index].enabled = enabled;
      }
    },
    // 用户偏好设置
    setPreferences(userPreferences) {
      this.userPreferences = userPreferences;
      localStorage.setItem('userPreferences', JSON.stringify(userPreferences));
    },
    // 更新用户偏好设置
    updatePreference(key, value) {
      this.userPreferences[key] = value;
      localStorage.setItem('userPreferences', JSON.stringify(this.userPreferences));
    },
    // 从本地存储加载用户偏好设置
    loadPreferences() {
      const defaultPreferences = {
        theme: 'auto', // auto, light, dark
        connectivityAutoRefresh: false,
        showMap: false,
        simpleMode: false,
        autoStart: true,
        hideUnavailableIPStack: false,
        popupConnectivityNotifications: true,
        ipCardsToShow: 6,
        ipGeoSource: 0,
        lang: 'auto',
      };
      const storedPreferences = localStorage.getItem('userPreferences');
      let preferencesToStore;

      if (storedPreferences) {
        const currentPreferences = JSON.parse(storedPreferences);
        preferencesToStore = { ...defaultPreferences, ...currentPreferences };
      } else {
        preferencesToStore = defaultPreferences;
      }

      localStorage.setItem('userPreferences', JSON.stringify(preferencesToStore));
      this.setPreferences(preferencesToStore);
    },
    // 从服务器获取配置
    async fetchConfigs() {
      try {
        const data = await this.aggregateApiFetch('/api/configs');
        this.configs = data;
      } catch (error) {
        console.error('Fetching configs failed: ', error);
      }
    },
  }
});