<template>
    <div class="backend-content" id="content">
        <div class="column col-8 col-xs-12">
            <h3 class="s-title">Post-exposure quarantine</h3>
            <p class="text-gray" style="margin-bottom:1rem">
                Declare a quarantine window after a major CTI publication (e.g. Amnesty Tech, Citizen Lab).
                During an active window, detection thresholds are hardened to surface rebuilt spyware infrastructure.
            </p>
            <ul class="tab tab-block">
                <li class="tab-item">
                    <a href="#" v-on:click="switch_tab('add')" v-bind:class="{ active: tabs.add }">Declare event</a>
                </li>
                <li class="tab-item">
                    <a href="#" v-on:click="switch_tab('list')" v-bind:class="{ active: tabs.list }">Quarantine events</a>
                </li>
            </ul>

            <!-- Add form -->
            <div v-if="tabs.add">
                <div class="misp-form">
                    <label class="misp-label">Event name <span class="text-error">*</span></label><span></span>
                    <input class="form-input" type="text" placeholder="Pegasus cluster 2024-07"
                           v-model="form.name" required>
                    <label class="misp-label">Source / reason</label><span></span>
                    <input class="form-input" type="text" placeholder="Amnesty Tech report, July 2024"
                           v-model="form.reason">
                    <label class="misp-label">Duration (days)</label><span></span>
                    <input class="form-input" type="number" min="1" max="365"
                           v-model.number="form.duration_days">
                </div>
                <button class="btn-primary btn col-12" v-on:click="add_event()">Declare quarantine event</button>
                <div class="form-group" style="margin-top:0.8rem" v-if="added">
                    <div class="toast toast-success">✓ Quarantine event declared. Redirecting to events list.</div>
                </div>
                <div class="form-group" style="margin-top:0.8rem" v-if="error">
                    <div class="toast toast-error">✗ {{ error }}</div>
                </div>
            </div>

            <!-- Events list -->
            <div v-if="tabs.list">
                <div v-if="events.length">
                    <table class="table table-striped table-hover">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Reason</th>
                                <th>Started</th>
                                <th>Expires</th>
                                <th>Status</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr v-for="e in events" v-bind:key="e.id">
                                <td>{{ e.name }}</td>
                                <td class="text-gray">{{ e.reason || '—' }}</td>
                                <td>{{ fmt_date(e.started_at) }}</td>
                                <td>{{ fmt_date(e.expires_at) }}</td>
                                <td>
                                    <span v-if="e.active" class="label label-success">ACTIVE</span>
                                    <span v-else class="label">EXPIRED</span>
                                </td>
                                <td><button class="btn btn-sm" v-on:click="delete_event(e)">Delete</button></td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                <div v-else>
                    <div class="empty">
                        <p class="empty-title h5">No quarantine events.</p>
                        <p class="empty-subtitle">Declare an event after a major spyware exposure report.</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>

<script>
import axios from 'axios'

export default {
    name: 'ctiquarantine',
    data() {
        return {
            jwt: '',
            error: false,
            added: false,
            events: [],
            form: { name: '', reason: '', duration_days: 42 },
            tabs: { add: true, list: false },
        }
    },
    methods: {
        fmt_date(ts) {
            return new Date(ts * 1000).toLocaleDateString(undefined, {
                year: 'numeric', month: 'short', day: 'numeric'
            })
        },
        switch_tab(tab) {
            Object.keys(this.tabs).forEach(k => {
                this.tabs[k] = k === tab
            })
            if (tab === 'list') this.load_events()
        },
        add_event() {
            this.added = false
            this.error = false
            if (!this.form.name.trim()) {
                this.error = 'Event name is required.'
                return
            }
            axios.post('/api/cti/quarantine/add', {
                name: this.form.name,
                reason: this.form.reason,
                duration_days: this.form.duration_days,
            }, { headers: { 'X-Token': this.jwt } })
            .then(response => {
                if (response.data.status) {
                    this.added = true
                    setTimeout(() => {
                        this.form = { name: '', reason: '', duration_days: 42 }
                        this.added = false
                        this.switch_tab('list')
                    }, 1500)
                } else {
                    this.error = response.data.message
                }
            })
            .catch(err => console.log(err))
        },
        delete_event(ev) {
            axios.delete(`/api/cti/quarantine/delete/${ev.id}`, {
                headers: { 'X-Token': this.jwt }
            })
            .then(response => {
                if (response.data.status) {
                    this.events = this.events.filter(e => e.id !== ev.id)
                }
            })
            .catch(err => console.log(err))
        },
        load_events() {
            axios.get('/api/cti/quarantine', { headers: { 'X-Token': this.jwt } })
            .then(response => {
                if (response.data.status) {
                    this.events = response.data.results.sort((a, b) => b.started_at - a.started_at)
                }
            })
            .catch(err => console.log(err))
        },
        get_jwt() {
            axios.get('/api/get-token', { timeout: 10000 })
            .then(response => {
                if (response.data.token) this.jwt = response.data.token
            })
            .catch(err => console.log(err))
        },
    },
    created() {
        this.get_jwt()
    }
}
</script>
