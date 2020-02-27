import { menu, router, user } from "@core";
import * as React from "react";
import { Server } from 'https';

export const registerContactUs = {
	async register() {
		menu.items.push({
			icon: "Contact",
			name: "Contact Us",
			key: "Contact Us",
			onClick: () => {
				window.location.href = "https://www.wedentists.com";
			},
			order: 998,
			url: ""
		});
		
		return true;
	},
	order: 9
};
