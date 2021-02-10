//@ts-check
/*
  Copyright: (c) 2021, ST-One
  GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
*/

const {melsecAdapter} = require('node-melsec');

const MIN_CYCLE_TIME = 50;

module.exports = function (RED) {
    // ----------- Focas Endpoint -----------
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
    
    // <Begin> --- Endpoint ---
    function MelsecEndpoint(config) {
        let oldValues = {};
        let readInProgress = false;
        let readDeferred = 0;
        let currentCycleTime = config.cycletime;
        let _td;
        let that = this
        
        RED.nodes.createNode(this, config);

        //avoids warnings when we have a lot of Melsec In nodes
        this.setMaxListeners(0);

        function doCycle() {
            if (!readInProgress) {
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

            if (readDeferred) {
                doCycle();
                readDeferred = 0;
            }

            //manageStatus('online');

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
                return
            }

            clearInterval(_td);

            // don't set a new timer if value is zero
            if (!time) return;

            if (time < MIN_CYCLE_TIME) {
                that.warn(RED._("melsec.endpoint.info.cycletimetooshort", { min: MIN_CYCLE_TIME }));
                time = MIN_CYCLE_TIME;
            } 

            currentCycleTime = time;
            _td = setInterval(doCycle, time);
        }

        async function melsecSetUp(vars) {
            await melsec.open()
            .then(() => {
                melsec.setTranslationCB(k => vars[k]);

                let varKeys = Object.keys(vars);
                if (!varKeys || !varKeys.length) {
                    that.warn(RED._("melsec.endpoint.info.novars"));
                } else {
                    melsec.addAddress(varKeys);
                }
                return;
            })
            .catch(e => {
                that.error(e);
                throw e;
            });
        }

        let _vars = createTranslationTable(config.vartable);

        const melsec = new melsecAdapter();

        melsecSetUp(_vars).then(() => {
            updateCycleTime(currentCycleTime);
        });

        this.on('close', done => {
            
            if (_td) clearInterval(_td);
            melsec.close().then(done).catch(e => {
                that.error(e);
                done(e);
            });;
        });
        
    }

    RED.nodes.registerType('melsec endpoint', MelsecEndpoint);
    // <End> --- Config

    // <Begin> --- Melsec In
    function MelsecIn(config) {
        RED.nodes.createNode(this, config);
        let that = this

        let endpoint = RED.nodes.getNode(config.endpoint);

        if (!endpoint) {
            that.error(RED._("melsec.in.error.missingconfig"));
            return;
        }

        function sendMsg(data, key) {
            if (key === undefined) key = '';
            if (data instanceof Date) data = data.getTime();
            var msg = {
                payload: data,
                topic: key
            };
            that.send(msg);
        }
        
        function onChanged(variable) {
            sendMsg(variable.value, variable.key);
        }

        function onDataSplit(data) {
            Object.keys(data).forEach(function (key) {
                sendMsg(data[key], key);
            });
        }

        function onData(data) {
            sendMsg(data, config.mode == 'single' ? config.variable : '');
        }

        function onDataSelect(data) {
            onData(data[config.variable]);
        }

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
            endpoint.removeListener(config.variable, onData);
            done();
        });

    }

    RED.nodes.registerType('melsec in', MelsecIn);
    // <End> --- Node

};
