require("dotenv").config();

const { Client, Intents, MessageEmbed } = require("discord.js");
const client = new Client({
    intents: [Intents.FLAGS.GUILDS, Intents.FLAGS.GUILD_MESSAGES],
});

const VirusTotalApi = require("virustotal-api");
const virusTotal = new VirusTotalApi(process.env.VT_API_KEY);

const { Scanner } = require("url-safety-scanner");
const myScanner = Scanner({
    apiKey: process.env.GOOGLE_API_KEY,
    clientId: "guardian-v2-323704",
});

const { find } = require("linkifyjs");

const createAnalysisEmbed = (result) => {
    return new MessageEmbed()
        .setTitle(`Analysis`)
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
};

client.on("interactionCreate", async (interaction) => {
    if (!interaction.isCommand()) return;

    if (interaction.commandName === "ping") {
        await interaction.reply("Pong!");
    }

    if (interaction.commandName === "analyze") {
        const url = interaction.options.getString("url");
        if (!url) return interaction.reply("Please provide a URL to analyze.");
        console.log(url);

        const result = await virusTotal.urlReport(url, false, 1);

        interaction.reply({ embeds: [createAnalysisEmbed(result)] });
    }
});

client.on("messageCreate", async (message) => {
    console.log(message);
    const results = find(message.content).filter((i) => i.type === "url");
    if (results.length > 0) {
        for (var i = 0; i < results.length; i++) {
            const vt_result = await virusTotal.urlReport(results[i].url);
        }
    }
});

client.on("ready", () => {
    console.log(`Logged in as ${client.user.username}`);
});

client.login(process.env.DISCORD_TOKEN);
