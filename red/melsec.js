//@ts-check
/*
  Copyright: (c) 2021, ST-One
  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
*/

const {melsecAdapter} = require('node-melsec');

const MIN_CYCLE_TIME = 50;

module.exports = function (RED) {
    // ----------- Melsec Endpoint -----------
    function generateStatus(status, val) {
        var obj;
        if (typeof val != 'string' && typeof val != 'number' && typeof val != 'boolean') {
            val = RED._('melsec.endpoint.status.online');
        }
        switch (status) {
            case 'online':
                obj = {
                    fill: 'green',
                    shape: 'dot',
                    text: val.toString()
                };
                break;
            case 'offline':
                obj = {
                    fill: 'red',
                    shape: 'dot',
                    text: RED._('melsec.endpoint.status.offline')
                };
                break;
            case 'connecting':
                obj = {
                    fill: 'yellow',
                    shape: 'dot',
                    text: RED._('melsec.endpoint.status.connecting')
                };
                break;
            default:
                obj = {
                    fill: 'grey',
                    shape: 'dot',
                    text: RED._('melsec.endpoint.status.unknown')
                };
        }
        return obj;
    }

    function createTranslationTable(vars) {
        var res = {};

        vars.forEach(function (elm) {
            if (!elm.name || !elm.addr) {
                //skip incomplete entries
                return;
            }
            res[elm.name] = elm.addr;
        });

        return res;
    }

    function equals(a, b) {
        if (a === b) return true;
        if (a == null || b == null) return false;
        if (a instanceof Date && b instanceof Date) return a.getTime() === b.getTime();
        if (Array.isArray(a) && Array.isArray(b)) {
            if (a.length != b.length) return false;
    
            for (var i = 0; i < a.length; ++i) {
                if (a[i] !== b[i]) return false;
            }
            return true;
        }
        return false;
    }

    function nrInputShim(node, fn) {
        node.on('input', function (msg, send, done) {
            send = send || node.send;
            done = done || (err => err && node.error(err, msg));
            fn(msg, send, done);
        });
    }
    
    // <Begin> --- Endpoint ---
    function MelsecEndpoint(config) {
        let oldValues = {};
        let readInProgress = false;
        let readDeferred = 0;
        let currentCycleTime = config.cycletime;
        let _cycleInterval;
        let _reconnectInterval = null;
        let connected = false;
        let connecting = false;
        let status;
        let that = this;
        
        RED.nodes.createNode(this, config);

        //avoids warnings when we have a lot of Melsec In nodes
        this.setMaxListeners(0);

        function manageStatus(newStatus) {
            if (status == newStatus) return;

            status = newStatus;
            that.emit('__STATUS__', status);
        }
        
        function doCycle() {
            if (!readInProgress && connected) {
                melsec.readAllAddresses().then(cycleCallback).catch(e => {
                    that.error(e);
                    readInProgress = false;
                });
                readInProgress = true;
            } else {
                readDeferred++;
            }
        }

        function cycleCallback(values) {
            readInProgress = false;

            if (readDeferred && connected) {
                doCycle();
                readDeferred = 0;
            }

            manageStatus('online');

            var changed = false;
            that.emit('__ALL__', values);
            Object.keys(values).forEach(function (key) {
                if (!equals(oldValues[key], values[key])) {
                    changed = true;
                    that.emit(key, values[key]);
                    that.emit('__CHANGED__', {
                        key: key,
                        value: values[key]
                    });
                    oldValues[key] = values[key];
                }
            });
            if (changed) that.emit('__ALL_CHANGED__', values);
        }

        function updateCycleTime(interval) {
            let time = parseInt(interval);

            if (isNaN(time) || time < 0) {
                that.error(RED._("melsec.endpoint.error.invalidtimeinterval", { interval: interval }));
                return false
            }

            clearInterval(_cycleInterval);

            // don't set a new timer if value is zero
            if (!time) return false;

            if (time < MIN_CYCLE_TIME) {
                that.warn(RED._("melsec.endpoint.info.cycletimetooshort", { min: MIN_CYCLE_TIME }));
                time = MIN_CYCLE_TIME;
            } 

            currentCycleTime = time;
            _cycleInterval = setInterval(doCycle, time);

            return true;
        }

        function onConnect() {
            if (_reconnectInterval) {
                clearInterval(_reconnectInterval);
                _reconnectInterval = null;
            }

            connecting = false;
            readInProgress = false;
            readDeferred = 0;
            connected = true;

            manageStatus('online');

            let _vars = createTranslationTable(config.vartable);

            melsec.setTranslationCB(k => _vars[k]);

            let varKeys = Object.keys(_vars);
            if (!varKeys || !varKeys.length) {
                that.warn(RED._("melsec.endpoint.info.novars"));
            } else {
                melsec.removeAddress(varKeys);
                melsec.addAddress(varKeys);
            }

            updateCycleTime(currentCycleTime);
        }

        function reconnect() {
            melsec.close()
            .then(() => {
                if (!connecting) {
                    connecting = true;
                    manageStatus('connecting');
                    melsec.open().catch((e) => {
                        connecting = false;
                        onError(e);
                    });
                }
            })
            .catch(onError);
        }

        function onDisconnect() {
            manageStatus('offline');
            connected = false;
            if (!_reconnectInterval) {
                _reconnectInterval = setInterval(reconnect, 1000);
            }
        }

        function onError(e) {
            manageStatus('offline');
            that.error(e && e.toString());
        }

        manageStatus('offline');
        
        const melsec = new melsecAdapter();

        melsec.on('connect', onConnect);
        melsec.on('disconnect', onDisconnect);
        melsec.on('error', onError);

        connecting = true;
        
        manageStatus('connecting');

        melsec.open().catch((e) => {
            connecting = false;
            onError(e);
            onDisconnect();
        });

        this.on('__DO_CYCLE__', doCycle);
        this.on('__UPDATE_CYCLE__', (obj) => {
            obj.err = updateCycleTime(obj.msg.payload);
            that.emit('__UPDATE_CYCLE_RES__', obj);
        });
        this.on('__GET_STATUS__', () => {
            that.emit('__STATUS__', status);
        });

        this.on('close', done => {
            manageStatus('offline');
            if (_cycleInterval) clearInterval(_cycleInterval);

            this.removeAllListeners();
            melsec.removeAllListeners();

            melsec.close()
            .then(() => {
                done();
            })
            .catch(e => {
                that.error(e);
                done(e);
            });
        });
        
    }

    RED.nodes.registerType('melsec fx endpoint', MelsecEndpoint);
    // <End> --- Endpoint

    // <Begin> --- Melsec In
    function MelsecIn(config) {
        RED.nodes.createNode(this, config);
        let statusVal;
        let that = this

        let endpoint = RED.nodes.getNode(config.endpoint);

        if (!endpoint) {
            that.error(RED._("melsec.error.missingconfig"));
            return;
        }

        function sendMsg(data, key, status) {
            if (key === undefined) key = '';
            if (data instanceof Date) data = data.getTime();
            var msg = {
                payload: data,
                topic: key
            };
            statusVal = status !== undefined ? status : data;
            that.send(msg);
            endpoint.emit('__GET_STATUS__');
        }
        
        function onChanged(variable) {
            sendMsg(variable.value, variable.key, null);
        }

        function onDataSplit(data) {
            Object.keys(data).forEach(function (key) {
                sendMsg(data[key], key, null);
            });
        }

        function onData(data) {
            sendMsg(data, config.mode == 'single' ? config.variable : '');
        }

        function onDataSelect(data) {
            onData(data[config.variable]);
        }

        function onEndpointStatus(status) {
            that.status(generateStatus(status, statusVal));
        }
        
        endpoint.on('__STATUS__', onEndpointStatus);
        endpoint.emit('__GET_STATUS__');

        if (config.diff) {
            switch (config.mode) {
                case 'all-split':
                    endpoint.on('__CHANGED__', onChanged);
                    break;
                case 'single':
                    endpoint.on(config.variable, onData);
                    break;
                case 'all':
                default:
                    endpoint.on('__ALL_CHANGED__', onData);
            }
        } else {
            switch (config.mode) {
                case 'all-split':
                    endpoint.on('__ALL__', onDataSplit);
                    break;
                case 'single':
                    endpoint.on('__ALL__', onDataSelect);
                    break;
                case 'all':
                default:
                    endpoint.on('__ALL__', onData);
            }
        }

        this.on('close', function (done) {
            endpoint.removeListener('__ALL__', onDataSelect);
            endpoint.removeListener('__ALL__', onDataSplit);
            endpoint.removeListener('__ALL__', onData);
            endpoint.removeListener('__ALL_CHANGED__', onData);
            endpoint.removeListener('__CHANGED__', onChanged);
            endpoint.removeListener('__STATUS__', onEndpointStatus);
            endpoint.removeListener(config.variable, onData);
            done();
        });

    }

    RED.nodes.registerType('melsec fx in', MelsecIn);
    // <End> --- Melsec In

    // <Begin> --- Melsec Control
    function MelsecControl(config) {
        let that = this;
        RED.nodes.createNode(this, config);

        let endpoint = RED.nodes.getNode(config.endpoint);

        if (!endpoint) {
            this.error(RED._("melsec.error.missingconfig"));
            return;
        }

        function onEndpointStatus(status) {
            that.status(generateStatus(status));
        }

        function onMessage(msg, send, done) {
            let func = config.function || msg.function;
            switch (func) {
                case 'cycletime':
                    endpoint.emit('__UPDATE_CYCLE__', {
                        msg: msg,
                        send: send,
                        done: done
                    });
                    break;
                case 'trigger':
                    endpoint.emit('__DO_CYCLE__');
                    send(msg);
                    done();
                    break;

                default:
                    this.error(RED._("melsec.error.invalidcontrolfunction", { function: config.function }), msg);
            }
        }

        function onUpdateCycle(res) {
            let err = res.err;
            if (!err) {
                res.done(err);
            } else {
                res.send(res.msg);
                res.done();
            }
        }

        endpoint.on('__STATUS__', onEndpointStatus);
        endpoint.on('__UPDATE_CYCLE_RES__', onUpdateCycle);

        endpoint.emit('__GET_STATUS__');

        nrInputShim(this, onMessage);

        this.on('close', function (done) {
            endpoint.removeListener('__STATUS__', onEndpointStatus);
            endpoint.removeListener('__UPDATE_CYCLE_RES__', onUpdateCycle);
            done();
        });

    }
    RED.nodes.registerType("melsec fx control", MelsecControl);
    // <End> --- Melsec Control
};
