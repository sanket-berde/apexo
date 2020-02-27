import { connectToDB, menu, router, user } from "@core";
import { EndoCase, endoCases, endoNamespace, setting } from "@modules";
import * as React from "react";
export const registerEndodontic = {
	async register() {
		router.register({
			namespace: endoNamespace,
			regex: /^endodontic/,
			component: async () => {
				const Component = (await import("./components/page.endodontic"))
					.EndoPage;
				return <Component />;
			},
			condition: () =>
				!!setting.getSetting("module_endodontics") &&
				user.currentUser.canViewOrtho
		});
		menu.items.push({
			icon: "MiniLink",
			name: endoNamespace,
			key: endoNamespace,
			onClick: () => {
				router.go([endoNamespace]);
			},
			order:6,
			url: "",

			condition: () =>
				user.currentUser.canViewOrtho &&
				!!setting.getSetting("module_endodontics")
		});
		await ((await connectToDB(endoNamespace, endoNamespace)) as any)(
			EndoCase,
			endoCases
		);
		return true;
	},
	order: 7
};
