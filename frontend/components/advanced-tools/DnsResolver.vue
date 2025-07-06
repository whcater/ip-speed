<template>
    <!-- DNS Resolver -->
    <div class="dns-resolver-section my-4">
        <div class="text-secondary">
            <p>{{ t('dnsresolver.Note') }}</p>
        </div>
        <div class="row">
            <div class="col-12 mb-3">
                <div class="card jn-card" :class="{ 'dark-mode dark-mode-border': isDarkMode }">
                    <div class="card-body">
                        <div class="col-12 col-md-auto">
                            <label for="queryURL" class="col-form-label">{{ t('dnsresolver.Note2') }}</label>
                        </div>


                        <div class="input-group mb-2 mt-2 ">
                            <input type="text" class="form-control" :class="{ 'dark-mode': isDarkMode }"
                                :disabled="dnsCheckStatus === 'running'" :placeholder="t('dnsresolver.Placeholder')"
                                v-model="queryURL" @keyup.enter="onSubmit" name="queryURL" id="queryURL" data-1p-ignore>

                            <button type="button" class="btn btn-primary dropdown-toggle dropdown-toggle-split"
                                data-bs-toggle="dropdown" aria-expanded="false"
                                :disabled="dnsCheckStatus === 'running' || !queryURL">
                                {{ queryType }} {{ t('dnsresolver.Record') }}
                                <span class="visually-hidden">Choose Type</span>
                            </button>
                            <ul class="dropdown-menu dropdown-menu-end">
                                <li @click="changeType('A')"><span class="dropdown-item">A</span></li>
                                <li @click="changeType('AAAA')"><span class="dropdown-item">AAAA</span></li>
                                <li @click="changeType('CNAME')"><span class="dropdown-item">CNAME</span></li>
                                <li @click="changeType('MX')"><span class="dropdown-item">MX</span></li>
                                <li @click="changeType('NS')"><span class="dropdown-item">NS</span></li>
                                <li @click="changeType('TXT')"><span class="dropdown-item">TXT</span></li>
                            </ul>
                            <button class="btn btn-primary" @click="onSubmit"
                                :disabled="dnsCheckStatus === 'running' || !queryURL">
                                <span v-if="dnsCheckStatus === 'idle'">{{
                                    t('dnsresolver.Run') }}</span>
                                <span v-if="dnsCheckStatus === 'running'" class="spinner-grow spinner-grow-sm"
                                    aria-hidden="true"></span>
                            </button>

                        </div>
                        <div class="jn-placeholder">
                            <p v-if="errorMsg" class="text-danger">{{ errorMsg }}</p>
                        </div>

                        <!-- Results Table -->
                        <div v-if="combinedResults && combinedResults.length">
                            <div class="table-responsive text-nowrap">
                                <table class="table table-hover" :class="{ 'table-dark': isDarkMode }">
                                    <thead>
                                        <tr>
                                            <th scope="col">{{ t('dnsresolver.Provider') }}</th>
                                            <th scope="col">{{ t('dnsresolver.Result') }}</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr v-for="(result, index) in combinedResults" :key="index">
                                            <td>{{ result.provider }}</td>
                                            <td :class="[result.address === 'N/A' ? 'opacity-50' : ''  ]">{{
                                                result.address }}</td>
                                        </tr>

                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>

<script setup>
import { ref, computed } from 'vue';
import { useMainStore } from '@/store';
import { useI18n } from 'vue-i18n';
import { trackEvent } from '@/utils/use-analytics';

const { t } = useI18n();

const store = useMainStore();
const isDarkMode = computed(() => store.isDarkMode);
const isMobile = computed(() => store.isMobile);


const queryURL = ref('');
const queryType = ref('A');
const dnsCheckStatus = ref('idle');
const errorMsg = ref('');
const combinedResults = ref([]);

// 检查 URL 输入是否有效
const validateInput = (input) => {
    // 检查是否包含协议头，若没有则尝试为其添加 http:// 以便进行 URL 格式验证
    if (!input.match(/^https?:\/\//)) {
        input = 'http://' + input;
    }

    try {
        const url = new URL(input);
        const hostname = url.hostname;

        if (hostname.match(/^[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/i)) {
            return hostname;
        }
    } catch {
    }

    errorMsg.value = t('dnsresolver.invalidURL');
    return null;
};

const changeType = (type) => {
    queryType.value = type;
};

const onSubmit = () => {
    trackEvent('Section', 'StartClick', 'DNSResolver');
    errorMsg.value = '';
    const hostname = validateInput(queryURL.value);
    const type = queryType.value;
    if (hostname) {
        getDNSResults(hostname, type);
    }
};

// 获取DNS结果
const getDNSResults = async (hostname, type) => {
    combinedResults.value = [];
    dnsCheckStatus.value = 'running';
    try {
        const data = await store.aggregateApiFetch('/api/dnsresolver', {
            hostname: hostname,
            type: type
        });
        processResults(data);
        dnsCheckStatus.value = 'idle';
        errorMsg.value = '';
    } catch (error) {
        console.error('Error fetching DNS results:', error);
        dnsCheckStatus.value = 'idle';
        errorMsg.value = t('dnsresolver.fetchError');
    }
};

const processResults = (data) => {
    const processEntries = (entries, type) => entries.map(entry => {
        const provider = Object.keys(entry)[0];
        const address = Array.isArray(entry[provider]) ? entry[provider].join(', ') : entry[provider];
        return { provider: `${provider} (${type})`, address };
    });

    if (data.result_dns) {
        combinedResults.value.push(...processEntries(data.result_dns, 'DNS'));
    }
    if (data.result_doh) {
        combinedResults.value.push(...processEntries(data.result_doh, 'DoH 🔒'));
    }
};

</script>

<style scoped>
.jn-placeholder {
    height: 16pt;
}
</style>
