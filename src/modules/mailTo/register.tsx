import { menu  } from "@core";
import * as React from "react";

export const registerMailTo = {
	async register() {
		menu.items.push({
			icon: "Mail",
			name: "Mail To",
			key: "Mail to",
			onClick: () => {
				var link = document.createElement('a');
				link.href = "mailto:contact@365apex.com";
				document.body.appendChild(link);
				link.click();
			},
			order: 999,
			url: "",
		});
		return true;
	},
	order: 9
};
