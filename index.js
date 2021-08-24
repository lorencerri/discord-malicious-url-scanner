require("dotenv").config();

// Discord.js
const {
    Client,
    Intents,
    MessageEmbed,
    MessageButton,
    MessageActionRow,
} = require("discord.js");
const intents = [Intents.FLAGS.GUILDS, Intents.FLAGS.GUILD_MESSAGES];
const client = new Client({ intents });

const linkify = require("linkifyjs"); // Linkify (Scans text for URLs)
const VirusTotalAPI = require("virustotal-api"); // VirusTotal (Scans URLs)
const virusTotal = new VirusTotalAPI(process.env.VT_API_KEY);

// Button Handler
client.on("interactionCreate", (interaction) => {
    if (!interaction.isButton()) return;

    // Handle descriptive buttons
    if (interaction.customId === "_") {
        interaction.reply({
            ephemeral: true,
            content: "*This button just displays information...*",
        });
    }

    const executor = interaction.member;
    const action = interaction.customId.split("_")[0];

    if (action === "ban") {
        if (!executor.roles.cache.find((r) => r.name === "Moderator"))
            return interaction.reply({
                ephemeral: true,
                content: "You do not have permission to use this button.",
            });

        const sender = interaction.member.guild.members.cache.get(
            interaction.customId.split("_")[1]
        );
        sender.ban({ days: 1, reason: "Banned by moderator" });

        const row = new MessageActionRow().addComponents(
            new MessageButton()
                .setCustomId("_")
                .setLabel(`Successfully banned by ${executor.user.tag}!`)
                .setStyle("SUCCESS")
        );

        interaction.message.edit({ components: [row] });
    }
});

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
    // ignoring certain files isn't necessary, it's only to ensure VirusTotal ratelimits aren't met

    for (var i = 0; i < urls.length; i++) {
        const url = urls[i].value;
        console.log(`Scanning ${url}`);

        // Catch Rate Limit Errors
        var result;
        try {
            result = await virusTotal.urlReport(url, false, 1);
        } catch (err) {}

        // Ignore Kaspersky (high false positives)
        if (result?.scans?.Kaspersky?.detected) result.positives -= 1;
        total -= 1;

        // Positive Results
        if (result && result.positives > 0) {
            // Delete Message
            message.delete();

            // Add Muted Role
            const mutedRole = message.guild.roles.cache.find(
                (role) => role.name === "Muted"
            );
            message.member.roles.add(mutedRole);

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

            // Add ban prompt button
            const row = new MessageActionRow().addComponents(
                new MessageButton()
                    .setCustomId(`ban_${senderId}`)
                    .setLabel("Ban")
                    .setStyle("DANGER")
            );

            // Send Alert
            message.guild.channels.cache
                .get("873249087514894366")
                .send({ embeds: [embed], components: [row] });

            break;
        }
    }
});

// Ready Event
client.on("ready", () => {
    console.log(`Logged in as ${client.user.username}`);
});

// Login
client.login(process.env.DISCORD_TOKEN);
