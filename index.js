require("dotenv").config();

const { Client, Intents, MessageEmbed } = require("discord.js");
const client = new Client({
    intents: [Intents.FLAGS.GUILDS, Intents.FLAGS.GUILD_MESSAGES],
});

const VirusTotalApi = require("virustotal-api");
const virusTotal = new VirusTotalApi(process.env.VT_API_KEY);

const { find } = require("linkifyjs");

const createAnalysisEmbed = (result, malicious) => {
    const embed = new MessageEmbed()
        .setTitle(malicious ? "Malicious URL Detected" : `Analysis`)
        .setColor(0x5865f2)
        .setDescription(
            `🔗 \`${result.url}\`\nScan Date: \`${result.scan_date}\``
        )
        .addField(
            "Results",
            `Positives: \`${result.positives}\`\nNegatives: \`${
                result.total - result.positives
            }\`\nSafe? \`${result.positives > 0 ? "No" : "Yes"}\``
        );

    if (malicious) {
        embed.addField(
            "Actions Taken",
            "- Deleted Message\n- Added Muted Role"
        );
    }

    return embed;
};

client.on("interactionCreate", async (interaction) => {
    if (!interaction.isCommand()) return;

    if (interaction.commandName === "ping") {
        await interaction.reply("Pong!");
    } else if (interaction.commandName === "analyze") {
        const url = interaction.options.getString("url");
        if (!url) return interaction.reply("Please provide a URL to analyze.");
        const result = await virusTotal.urlReport(url, false, 1);
        interaction.reply({ embeds: [createAnalysisEmbed(result)] });
    }
});

client.on("messageCreate", async (message) => {
    if (message.author.bot) return;

    const results = find(message.content).filter((i) => i.type === "url");
    if (results.length > 0) {
        console.log(results);

        for (var i = 0; i < results.length; i++) {
            console.log(`Scanning ` + results[i].value);
            var vt_result;
            try {
                vt_result = await virusTotal.urlReport(
                    results[i].value,
                    false,
                    1
                );
            } catch (e) {
                return console.log("Rate Limit");
            }
            if (vt_result && vt_result.positives > 0) {
                message.delete();
                const mutedRole = message.guild.roles.cache.find(
                    (r) => r.name === "Muted"
                );
                if (mutedRole) message.member.roles.add(mutedRole);
                if (message.guild.id === "343572980351107077") {
                    message.guild.channels.cache
                        .get("398491167005868043")
                        .send({
                            embeds: [createAnalysisEmbed(vt_result, true)],
                        });
                }
            }
        }
    }
});

client.on("ready", () => {
    console.log(`Logged in as ${client.user.username}`);
});

client.login(process.env.DISCORD_TOKEN);
