import alasql from 'alasql';

export default class AccessDenialLog {
    constructor(
        public actorId: number | null,
        public actorUsername: string | null,
        public reason: string,
        public route: string,
        public ipAddress: string,
        public timestamp: Date = new Date(),
        public id?: number
    ) {}

    async create(): Promise<void> {
        await alasql.promise(`
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
    }

    static async getRecent(limit = 50): Promise<AccessDenialLog[]> {
        const results = await alasql.promise(`
            SELECT * FROM access_denial_logs
            ORDER BY timestamp DESC
            LIMIT ${limit}
        `);
        return results.map((row: any) => new AccessDenialLog(
            row.actor_id,
            row.actor_username,
            row.reason,
            row.route,
            row.ip_address,
            new Date(row.timestamp),
            row.id
        ));
    }

    static async initializeTable(): Promise<void> {
        await alasql.promise(`
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
    }
}