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
class UserManagementLog {
    constructor(actorId, actorUsername, action, // 'delete', 'promote', 'demote'
    targetId, targetUsername, targetRole, timestamp = new Date(), id) {
        this.actorId = actorId;
        this.actorUsername = actorUsername;
        this.action = action;
        this.targetId = targetId;
        this.targetUsername = targetUsername;
        this.targetRole = targetRole;
        this.timestamp = timestamp;
        this.id = id;
    }
    create() {
        return __awaiter(this, void 0, void 0, function* () {
            yield alasql_1.default.promise(`
            INSERT INTO user_management_logs (actor_id, actor_username, action, target_id, target_username, target_role, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [
                this.actorId,
                this.actorUsername,
                this.action,
                this.targetId,
                this.targetUsername,
                this.targetRole,
                this.timestamp.toISOString()
            ]);
        });
    }
    static getRecent(limit = 50) {
        return __awaiter(this, void 0, void 0, function* () {
            const results = yield alasql_1.default.promise(`
            SELECT * FROM user_management_logs
            ORDER BY timestamp DESC
            LIMIT ${limit}
        `);
            return results.map((row) => new UserManagementLog(row.actor_id, row.actor_username, row.action, row.target_id, row.target_username, row.target_role, new Date(row.timestamp), row.id));
        });
    }
    static initializeTable() {
        return __awaiter(this, void 0, void 0, function* () {
            yield alasql_1.default.promise(`
            CREATE TABLE IF NOT EXISTS user_management_logs(
                id serial primary key not null autoincrement,
                actor_id integer not null,
                actor_username text not null,
                action text not null,
                target_id integer not null,
                target_username text not null,
                target_role text not null,
                timestamp datetime not null
            );
        `);
        });
    }
}
exports.default = UserManagementLog;
//# sourceMappingURL=userManagementLog.js.map