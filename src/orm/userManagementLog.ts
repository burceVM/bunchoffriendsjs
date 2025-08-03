import alasql from 'alasql';

export default class UserManagementLog {
    constructor(
        public actorId: number,
        public actorUsername: string,
        public action: string, // 'delete', 'promote', 'demote'
        public targetId: number,
        public targetUsername: string,
        public targetRole: string,
        public timestamp: Date = new Date(),
        public id?: number
    ) {}

    async create(): Promise<void> {
        await alasql.promise(`
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
    }

    static async getRecent(limit = 50): Promise<UserManagementLog[]> {
        const results = await alasql.promise(`
            SELECT * FROM user_management_logs
            ORDER BY timestamp DESC
            LIMIT ${limit}
        `);
        return results.map((row: any) => new UserManagementLog(
            row.actor_id,
            row.actor_username,
            row.action,
            row.target_id,
            row.target_username,
            row.target_role,
            new Date(row.timestamp),
            row.id
        ));
    }

    static async initializeTable(): Promise<void> {
        await alasql.promise(`
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
    }
}