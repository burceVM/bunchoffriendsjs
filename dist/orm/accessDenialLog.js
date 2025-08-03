"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const alasql_1 = __importDefault(require("alasql"));
class AccessDenialLog {
    constructor(actorId, actorUsername, reason, route, ipAddress, timestamp = new Date(), id) {
        this.actorId = actorId;
        this.actorUsername = actorUsername;
        this.reason = reason;
        this.route = route;
        this.ipAddress = ipAddress;
        this.timestamp = timestamp;
        this.id = id;
    }
    create() {
        return __awaiter(this, void 0, void 0, function* () {
            yield alasql_1.default.promise(`
            INSERT INTO access_denial_logs (actor_id, actor_username, reason, route, ip_address, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        `, [
                this.actorId,
                this.actorUsername,
                this.reason,
                this.route,
                this.ipAddress,
                this.timestamp.toISOString()
            ]);
        });
    }
    static getRecent(limit = 50) {
        return __awaiter(this, void 0, void 0, function* () {
            const results = yield alasql_1.default.promise(`
            SELECT * FROM access_denial_logs
            ORDER BY timestamp DESC
            LIMIT ${limit}
        `);
            return results.map((row) => new AccessDenialLog(row.actor_id, row.actor_username, row.reason, row.route, row.ip_address, new Date(row.timestamp), row.id));
        });
    }
    static initializeTable() {
        return __awaiter(this, void 0, void 0, function* () {
            yield alasql_1.default.promise(`
            CREATE TABLE IF NOT EXISTS access_denial_logs(
                id serial primary key not null autoincrement,
                actor_id integer,
                actor_username text,
                reason text not null,
                route text not null,
                ip_address text not null,
                timestamp datetime not null
            );
        `);
        });
    }
}
exports.default = AccessDenialLog;
//# sourceMappingURL=accessDenialLog.js.map