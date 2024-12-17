package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func PrintBanner(textChoice int, bannerChoice int) {
	if bannerChoice == 1 {
		fmt.Println("  ,   A           {}           ,   A           {}")
		fmt.Println(" / \\, | ,        .--.         / \\, | ,        .--.")
		fmt.Println("|    =|= >      /.--.\\       |    =|= >      /.--.\\")
		fmt.Println(" \\ /` | `       |====|        \\ /` | `       |====|")
		fmt.Println("  `   |         |`::`|         `   |         |`::`|")
		fmt.Println("      |     .-;`\\..../`;_.-^-._    |     .-;`\\..../`;_.-^-._")
		fmt.Println("     /\\\\/  /  |...::..|`   :   `| /\\\\/  /  |...::..|`   :   `|")
		fmt.Println("     |:'\\ |   /'''::''|   .:.   | |:'\\ |   /'''::''|   .:.   |")
		fmt.Println("      \\ /\\;-,/\\   ::  |..:::::..|  \\ /\\;-,/\\   ::  |..:::::..|")
		fmt.Println("      |\\ <` >  >._::_.| ':::::' |  |\\ <` >  >._::_.| ':::::' |")
		fmt.Println("      | `\"\"`  /   ^^  |   ':'   |  | `\"\"`  /   ^^  |   ':'   |")
		fmt.Println("      |       |       \\    :    /  |       |       \\    :    /")
		fmt.Println("      |       |        \\   :   /   |       |        \\   :   /")
		fmt.Println("      |       |___/\\___|`-.:.-`    |       |___/\\___|`-.:.-`")
		fmt.Println("      |        \\_ || _/    `       |        \\_ || _/    `")
		fmt.Println("      |        <_ >< _>            |        <_ >< _>")
		fmt.Println("      |        |  ||  |            |        |  ||  |")
		fmt.Println("      |        |  ||  |            |        |  ||  |")
		fmt.Println("      |       _\\.:||:./_           |       _\\.:||:./")
		fmt.Println("      |      /____/\\____\\          |      /____/\\____\\")
	}
	if bannerChoice == 2 {
		fmt.Println("  ,   A           {}           ,   A           {}           ,   A           {}           ")
		fmt.Println(" / \\, | ,        .--.         / \\, | ,        .--.         / \\, | ,        .--.        ")
		fmt.Println("|    =|= >      /.--.\\       |    =|= >      /.--.\\       |    =|= >      /.--.\\")
		fmt.Println(" \\ /` | `       |====|        \\ /` | `       |====|        \\ /` | `       |====|")
		fmt.Println("  `   |         |`::`|         `   |         |`::`|         `   |         |`::`|")
		fmt.Println("      |     .-;`\\..../`;_.-^-._    |     .-;`\\..../`;_.-^-._    |     .-;`\\..../`;_.-^-._")
		fmt.Println("     /\\\\/  /  |...::..|`   :   `| /\\\\/  /  |...::..|`   :   `| /\\\\/  /  |...::..|`   :   `|")
		fmt.Println("     |:'\\ |   /'''::''|   .:.   | |:'\\ |   /'''::''|   .:.   | |:'\\ |   /'''::''|   .:.   |")
		fmt.Println("      \\ /\\;-,/\\   ::  |..:::::..|  \\ /\\;-,/\\   ::  |..:::::..|  \\ /\\;-,/\\   ::  |..:::::..|")
		fmt.Println("      |\\ <` >  >._::_.| ':::::' |  |\\ <` >  >._::_.| ':::::' |  |\\ <` >  >._::_.| ':::::' |")
		fmt.Println("      | `\"\"`  /   ^^  |   ':'   |  | `\"\"`  /   ^^  |   ':'   |  | `\"\"`  /   ^^  |   ':'   |")
		fmt.Println("      |       |       \\    :    /  |       |       \\    :    /  |       |       \\    :    /")
		fmt.Println("      |       |        \\   :   /   |       |        \\   :   /   |       |        \\   :   /")
		fmt.Println("      |       |___/\\___|`-.:.-`    |       |___/\\___|`-.:.-`    |       |___/\\___|`-.:.-`")
		fmt.Println("      |        \\_ || _/    `       |        \\_ || _/    `       |        \\_ || _/    `")
		fmt.Println("      |        <_ >< _>            |        <_ >< _>            |        <_ >< _>")
		fmt.Println("      |        |  ||  |            |        |  ||  |            |        |  ||  |")
		fmt.Println("      |        |  ||  |            |        |  ||  |            |        |  ||  |")
		fmt.Println("      |       _\\.:||:./_           |       _\\.:||:./_           |       _\\.:||:./_")
		fmt.Println("      |      /____/\\____\\          |      /____/\\____\\          |      /____/\\____\\\n")
	}
	if textChoice == 1 {
		fmt.Println(":::     :::     :::     ::::    :::  ::::::::  :::    :::     :::     :::::::::  :::::::::")
		fmt.Println(":+:     :+:   :+: :+:   :+:+:   :+: :+:    :+: :+:    :+:   :+: :+:   :+:    :+: :+:    :+:")
		fmt.Println("+:+     +:+  +:+   +:+  :+:+:+  +:+ +:+        +:+    +:+  +:+   +:+  +:+    +:+ +:+    +:+")
		fmt.Println("+#+     +:+ +#++:++#++: +#+ +:+ +#+ :#:        +#+    +:+ +#++:++#++: +#++:++#:  +#+    +:+")
		fmt.Println(" +#+   +#+  +#+     +#+ +#+  +#+#+# +#+   +#+# +#+    +#+ +#+     +#+ +#+    +#+ +#+    +#+")
		fmt.Println("  #+#+#+#   #+#     #+# #+#   #+#+# #+#    #+# #+#    #+# #+#     #+# #+#    #+# #+#    #+#")
		fmt.Println("    ###     ###     ### ###    ####  ########   ########  ###     ### ###    ### #########")
		//fmt.Println("\t\t\t\t[ Version: 0.0.1 ]\n\t\t\t\t[ Author: emryll ]\n")
		fmt.Println("\t\t\t\t[ Author: emryll ]\n")
	}
	if textChoice == 2 {
		fmt.Println("     ##### /      ##                                                                    ##")
		fmt.Println("  ######  /    #####                                                                     ##")
		fmt.Println(" /#   /  /       #####                                                                   ##")
		fmt.Println("/    /  ##       / ##                                                                    ##")
		fmt.Println("    /  ###      /                                                                        ##")
		fmt.Println("   ##   ##      #   /###   ###  /###     /###    ##   ####      /###   ###  /###     ### ##")
		fmt.Println("   ##   ##      /  / ###  / ###/ #### / /  ###  / ##    ###  / / ###  / ###/ #### / #########")
		fmt.Println("   ##   ##     /  /   ###/   ##   ###/ /    ###/  ##     ###/ /   ###/   ##   ###/ ##   #### ")
		fmt.Println("   ##   ##     # ##    ##    ##    ## ##     ##   ##      ## ##    ##    ##        ##    ## ")
		fmt.Println("   ##   ##     / ##    ##    ##    ## ##     ##   ##      ## ##    ##    ##        ##    ## ")
		fmt.Println("    ##  ##    /  ##    ##    ##    ## ##     ##   ##      ## ##    ##    ##        ##    ## ")
		fmt.Println("     ## #     #  ##    ##    ##    ## ##     ##   ##      ## ##    ##    ##        ##    ## ")
		fmt.Println("      ###     /  ##    /#    ##    ## ##     ##   ##      /# ##    /#    ##        ##    /# ")
		fmt.Println("       ######/    ####/ ##   ###   ### ########    ######/ ## ####/ ##   ###        ####/  ")
		fmt.Println("         ###       ###   ##   ###   ###  ### ###    #####   ## ###   ##   ###        ###  ")
		fmt.Println("                                              ### ")
		fmt.Println("                                        ####   ### ")
		fmt.Println("                                      /######  /#  ")
		fmt.Println("                                     /     ###/\n")
	}
}

var rootCmd = &cobra.Command{
	Use:   "vanguard",
	Short: "A CLI at-rest encryption tool to secure your files",
	Long:  "Vanguard is a CLI tool you can use to encrypt and decrypt files or folders with AES-256 encryption, using salting and key derivation through PBKDF2.\nYou can use commands or the interactive shell.",
	Run:   startShell,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
	}
}

func main() {
	Execute()
}
