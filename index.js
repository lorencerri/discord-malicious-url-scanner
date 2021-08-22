require("dotenv").config();

// Discord.js
const { Client, Intents, MessageEmbed } = require("discord.js");
const intents = [Intents.FLAGS.GUILDS, Intents.FLAGS.GUILD_MESSAGES];
const client = new Client({ intents });

// Linkify (Scans text for URLs)
const linkify = require("linkifyjs");
const VirusTotalAPI = require("virustotal-api");
const virusTotal = new VirusTotalAPI(process.env.VT_API_KEY);

// Message Handler
client.on("messageCreate", async (message) => {
    if (message.author.bot) return;
    const senderId = message.author.id;

    // Match URLs in message
    const urls = linkify
        .find(message.content)
        .filter((i) => i.type === "url")
        .filter((i) => !i.value.startsWith("https://discord.com/")) // ignore discord links
        .filter((i) => !i.value.endsWith(".png")) // ignore png images
        .filter((i) => !i.value.endsWith(".mp4")); // ignore mp4 videos

    let action_taken = false;

    for (var i = 0; i < urls.length; i++) {
        if (action_taken) break;

        const url = urls[i].value;
        console.log(`Scanning ${url}`);

        // Catch Rate Limit Errors
        var result;
        try {
            result = await virusTotal.urlReport(url, false, 1);
        } catch (err) {}

        // Positive Results
        if (result && result.positives > 0) {
            action_taken = true;

            // Delete Message
            message.delete();

            // Add Muted Role
            const mutedRole = message.guild.roles.cache.find(
                (r) => r.name === "Muted"
            );
            if (mutedRole) message.member.roles.add(mutedRole);

            // Create Alert
            const embed = new MessageEmbed()
                .setTitle("Malicious URL Detected")
                .setColor(0x5865f2)
                .setURL(result.permalink)
                .setDescription(
                    `🔗 \`${url}\`\nScan Date: \`${result.scan_date}\``
                )
                .addField(
                    "Positives",
                    `\`${result.positives}/${result.total}\``,
                    true
                )
                .addField("Sender", `<@${senderId}> \`(${senderId})\``, true);

            // Send Alert
            message.guild.channels.cache
                .get("398491167005868043")
                .send({ embeds: [embed] });
        }
    }
});

// Ready Event
client.on("ready", () => {
    console.log(`Logged in as ${client.user.username}`);
});

// Login
client.login(process.env.DISCORD_TOKEN);
